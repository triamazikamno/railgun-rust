use super::{
    Arc, BTreeMap, BlindedCommitmentData, FixedBytes, PendingOutputPoiSubmitter, PoiError,
    PoiMerkleProof, PoiMerkleProofSource, PoiRpcClient, PoiStatus, PoiStatusReader,
    PreTransactionPoiError, SingleCommitmentProofContext, WalletPrivateRemoteAuthority,
};
use std::convert::Infallible;

/// Why a wallet-private remote effect was rejected before transport dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalletPrivateRemoteStale {
    Authority,
    Subject,
}

/// A private effect distinguishes stale work from an actual transport failure.
#[derive(Debug)]
pub(crate) enum WalletPrivateRemoteError<E, C = Infallible> {
    Stale(WalletPrivateRemoteStale),
    Check(C),
    Remote(E),
}

enum WalletPrivateRemoteAuthorizeError<C> {
    Stale(WalletPrivateRemoteStale),
    Check(C),
}

/// Generation/lifecycle fence shared by every wallet-private remote transport.
#[derive(Clone)]
struct WalletPrivateRemoteGate {
    authority: WalletPrivateRemoteAuthority,
}

/// Generic wallet-associated remote effect executor. The effect factory is invoked only
/// after authority and subject checks pass.
#[derive(Clone)]
pub(crate) struct WalletPrivateRemoteEffects {
    gate: WalletPrivateRemoteGate,
}

impl WalletPrivateRemoteEffects {
    #[must_use]
    pub(crate) const fn new(authority: WalletPrivateRemoteAuthority) -> Self {
        Self {
            gate: WalletPrivateRemoteGate::new(authority),
        }
    }

    pub(crate) async fn run<T, RemoteError, CheckError, Check, CheckFuture, Effect, EffectFuture>(
        &self,
        check_subject: Check,
        effect: Effect,
    ) -> Result<T, WalletPrivateRemoteError<RemoteError, CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
        Effect: FnOnce() -> EffectFuture,
        EffectFuture: std::future::Future<Output = Result<T, RemoteError>>,
    {
        match self.gate.authorize(check_subject).await {
            Ok(()) => {}
            Err(WalletPrivateRemoteAuthorizeError::Stale(reason)) => {
                return Err(WalletPrivateRemoteError::Stale(reason));
            }
            Err(WalletPrivateRemoteAuthorizeError::Check(error)) => {
                return Err(WalletPrivateRemoteError::Check(error));
            }
        }
        self.gate.dispatch(effect()).await
    }
}

impl WalletPrivateRemoteGate {
    const fn new(authority: WalletPrivateRemoteAuthority) -> Self {
        Self { authority }
    }

    async fn authorize<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
    ) -> Result<(), WalletPrivateRemoteAuthorizeError<CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.authority.revalidate().map_err(|_| {
            WalletPrivateRemoteAuthorizeError::Stale(WalletPrivateRemoteStale::Authority)
        })?;
        if !check_subject()
            .await
            .map_err(WalletPrivateRemoteAuthorizeError::Check)?
        {
            return Err(WalletPrivateRemoteAuthorizeError::Stale(
                WalletPrivateRemoteStale::Subject,
            ));
        }
        self.authority.revalidate().map_err(|_| {
            WalletPrivateRemoteAuthorizeError::Stale(WalletPrivateRemoteStale::Authority)
        })
    }

    async fn dispatch<T, E, C>(
        &self,
        effect: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, WalletPrivateRemoteError<E, C>> {
        self.authority
            .revalidate()
            .map_err(|_| WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority))?;
        tokio::select! {
            biased;
            () = self.authority.invalidated() => {
                Err(WalletPrivateRemoteError::Stale(WalletPrivateRemoteStale::Authority))
            }
            result = effect => result.map_err(WalletPrivateRemoteError::Remote),
        }
    }
}

/// Remote POI clients available to a wallet job only through generation/subject gates.
/// Raw transports are intentionally private so production call sites cannot bypass dispatch.
#[derive(Clone)]
pub(crate) struct WalletPrivatePoiClients {
    effects: WalletPrivateRemoteEffects,
    status: Arc<dyn PoiStatusReader>,
    proofs: Arc<dyn PoiMerkleProofSource>,
    submit: Arc<dyn PendingOutputPoiSubmitter>,
}

impl WalletPrivatePoiClients {
    pub(crate) fn from_rpc(authority: WalletPrivateRemoteAuthority, client: PoiRpcClient) -> Self {
        Self {
            effects: WalletPrivateRemoteEffects::new(authority),
            status: Arc::new(client.clone()),
            proofs: Arc::new(client.clone()),
            submit: Arc::new(client),
        }
    }

    #[must_use]
    pub(crate) fn remote_effects(&self) -> WalletPrivateRemoteEffects {
        self.effects.clone()
    }

    pub(crate) async fn pois_per_list<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<
        BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>,
        WalletPrivateRemoteError<PoiError, CheckError>,
    >
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.effects
            .run(check_subject, || {
                self.status.pois_per_list(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_keys,
                    blinded_commitment_datas,
                )
            })
            .await
    }

    pub(crate) async fn poi_merkle_proofs<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        blinded_commitments: &[FixedBytes<32>],
    ) -> Result<Vec<PoiMerkleProof>, WalletPrivateRemoteError<PreTransactionPoiError, CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.effects
            .run(check_subject, || {
                self.proofs.poi_merkle_proofs(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_key,
                    blinded_commitments,
                )
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn submit_single_commitment_proofs<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: &SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), WalletPrivateRemoteError<PoiError, CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.effects
            .run(check_subject, || {
                self.submit.submit_single_commitment_proofs(
                    txid_version,
                    chain_type,
                    chain_id,
                    context,
                    utxo_tree_out,
                    utxo_position_out,
                )
            })
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn submit_transact_proof<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        list_key: &FixedBytes<32>,
        txid_merkleroot_index: u64,
        poi: &broadcaster_core::transact::PreTxPoi,
    ) -> Result<(), WalletPrivateRemoteError<PoiError, CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.effects
            .run(check_subject, || {
                self.submit.submit_transact_proof(
                    txid_version,
                    chain_type,
                    chain_id,
                    list_key,
                    txid_merkleroot_index,
                    poi,
                )
            })
            .await
    }
}

#[cfg(test)]
impl WalletPrivatePoiClients {
    pub(crate) fn for_test(
        authority: WalletPrivateRemoteAuthority,
        status: Arc<dyn PoiStatusReader>,
        proofs: Arc<dyn PoiMerkleProofSource>,
        submit: Arc<dyn PendingOutputPoiSubmitter>,
    ) -> Self {
        Self {
            effects: WalletPrivateRemoteEffects::new(authority),
            status,
            proofs,
            submit,
        }
    }

    pub(crate) fn for_status(
        authority: WalletPrivateRemoteAuthority,
        status: Arc<dyn PoiStatusReader>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self::for_test(authority, status, unavailable.clone(), unavailable)
    }

    pub(crate) fn for_proofs(
        authority: WalletPrivateRemoteAuthority,
        proofs: Arc<dyn PoiMerkleProofSource>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self::for_test(authority, unavailable.clone(), proofs, unavailable)
    }

    pub(crate) fn for_submit(
        authority: WalletPrivateRemoteAuthority,
        submit: Arc<dyn PendingOutputPoiSubmitter>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self::for_test(authority, unavailable.clone(), unavailable, submit)
    }
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::wallet::async_trait;

    pub(super) struct UnavailablePrivatePoiTransport;

    #[async_trait]
    impl PoiStatusReader for UnavailablePrivatePoiTransport {
        async fn pois_per_list(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            _list_keys: &[FixedBytes<32>],
            _blinded_commitment_datas: &[BlindedCommitmentData],
        ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError>
        {
            Err(PoiError::MerkleRootsRejected)
        }
    }

    #[async_trait]
    impl PoiMerkleProofSource for UnavailablePrivatePoiTransport {
        async fn poi_merkle_proofs(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            _list_key: &FixedBytes<32>,
            _blinded_commitments: &[FixedBytes<32>],
        ) -> Result<Vec<PoiMerkleProof>, PreTransactionPoiError> {
            Err(PreTransactionPoiError::ProofSource(
                "private POI test transport unavailable".to_string(),
            ))
        }
    }

    #[async_trait]
    impl PendingOutputPoiSubmitter for UnavailablePrivatePoiTransport {
        async fn submit_single_commitment_proofs(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            _context: &SingleCommitmentProofContext,
            _utxo_tree_out: u64,
            _utxo_position_out: u64,
        ) -> Result<(), PoiError> {
            Err(PoiError::MerkleRootsRejected)
        }

        async fn submit_transact_proof(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            _list_key: &FixedBytes<32>,
            _txid_merkleroot_index: u64,
            _poi: &broadcaster_core::transact::PreTxPoi,
        ) -> Result<(), PoiError> {
            Err(PoiError::MerkleRootsRejected)
        }
    }
}
