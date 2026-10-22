use super::{
    Arc, BTreeMap, BlindedCommitmentData, Duration, FixedBytes, PendingOutputPoiSubmitter,
    PoiError, PoiRpcClient, PoiStatus, PoiStatusReader, SingleCommitmentProofContext, U256,
    WalletPrivateRemoteAuthority, debug,
};
use crate::chain::{
    PendingOutputPoiHandoff, PendingOutputPoiHandoffFailure, PendingOutputPoiSubmitIntent,
};
use crate::poi_submission::{PoiSubmissionAdmission, PoiSubmissionPermit, PoiSubmissionRouting};
use std::convert::Infallible;
use std::fmt;
use std::sync::{Mutex as StdMutex, PoisonError};

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

/// How a deferred submission was forced. A force-matching request outranks a
/// forced retry when both are deferred for one transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DeferredForceKind {
    /// A forced retry of submitted lists, still behind the recovery gate.
    RetrySubmitted,
    /// A force-resubmit of every matching list, with no recovery gate.
    ForceMatching,
}

/// Railgun TXIDs whose forced submission was deferred, with how each was
/// forced, kept for a reset generation so that later passes still force them
/// until one is admitted.
#[derive(Clone, Default)]
pub(crate) struct DeferredForcedSubmissions(Arc<StdMutex<BTreeMap<U256, DeferredForceKind>>>);

impl fmt::Debug for DeferredForcedSubmissions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeferredForcedSubmissions")
            .finish_non_exhaustive()
    }
}

impl DeferredForcedSubmissions {
    fn txids(&self) -> std::sync::MutexGuard<'_, BTreeMap<U256, DeferredForceKind>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One Railgun transaction's transact-proof route for a pass. Only
/// [`WalletPrivatePoiClients::reserve_transact_route`] builds one, so a
/// routed wallet never sends a transact proof over the shared client.
pub(crate) struct TransactProofRoute {
    railgun_txid: U256,
    /// `None` without a route provider: the shared POI client, as before.
    permit: Option<PoiSubmissionPermit>,
}

impl TransactProofRoute {
    pub(crate) const fn railgun_txid(&self) -> U256 {
        self.railgun_txid
    }
}

/// A transaction the scheduler did not admit this pass.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TransactProofsDeferred {
    /// When spacing ends; `None` when the route limit is full or the route
    /// failed to open.
    until: Option<tokio::time::Instant>,
}

impl TransactProofsDeferred {
    /// Wait before trying again; zero means the next pass.
    pub(crate) fn retry_after(self) -> Duration {
        self.until.map_or(Duration::ZERO, |until| {
            until.saturating_duration_since(tokio::time::Instant::now())
        })
    }
}

/// Remote POI clients available to a wallet job only through generation/subject gates.
/// Raw transports are intentionally private so production call sites cannot bypass dispatch.
/// Transact proofs go to the POI node directly, over a per-transaction route when the
/// chain has a route provider; single-commitment proofs are handed off to the chain
/// PPOI submitter.
#[derive(Clone)]
pub(crate) struct WalletPrivatePoiClients {
    effects: WalletPrivateRemoteEffects,
    status: Arc<dyn PoiStatusReader>,
    submit: Arc<dyn PendingOutputPoiSubmitter>,
    handoff: Arc<dyn PendingOutputPoiHandoff>,
    routing: Option<PoiSubmissionRouting>,
    forced_deferrals: DeferredForcedSubmissions,
}

impl WalletPrivatePoiClients {
    pub(crate) fn new(
        authority: WalletPrivateRemoteAuthority,
        client: PoiRpcClient,
        handoff: Arc<dyn PendingOutputPoiHandoff>,
    ) -> Self {
        Self {
            effects: WalletPrivateRemoteEffects::new(authority),
            status: Arc::new(client.clone()),
            submit: Arc::new(client),
            handoff,
            routing: None,
            forced_deferrals: DeferredForcedSubmissions::default(),
        }
    }

    /// Sends transact proofs over per-transaction routes when `routing` is
    /// set, recording forced ones it defers in `forced_deferrals`.
    #[must_use]
    pub(crate) fn with_submission_routing(
        mut self,
        routing: Option<PoiSubmissionRouting>,
        forced_deferrals: DeferredForcedSubmissions,
    ) -> Self {
        self.routing = routing;
        self.forced_deferrals = forced_deferrals;
        self
    }

    /// TXIDs whose forced submission is still deferred, with how each was
    /// forced. Snapshot at the start of a pass, since admission of a pending
    /// output's transaction removes a TXID.
    pub(crate) fn deferred_forced_txids(&self) -> BTreeMap<U256, DeferredForceKind> {
        self.forced_deferrals.txids().clone()
    }

    /// Ends the forced deferral of a pending output's transaction once it is
    /// admitted, however the current pass planned it.
    pub(crate) fn end_forced_deferral(&self, railgun_txid: U256) {
        self.forced_deferrals.txids().remove(&railgun_txid);
    }

    /// Admits one transaction's transact proofs. Without a route provider this
    /// always succeeds and sends over the shared client. With one, a deferral,
    /// failed route open or invalidated authority sends nothing; a `forced`
    /// deferral of a still valid job stays forced, the same way, for later
    /// passes until the transaction is admitted. Admission never ends a
    /// forced deferral; see [`Self::end_forced_deferral`].
    pub(crate) async fn reserve_transact_route(
        &self,
        chain_id: u64,
        railgun_txid: U256,
        forced: Option<DeferredForceKind>,
    ) -> Result<TransactProofRoute, TransactProofsDeferred> {
        let Some(routing) = &self.routing else {
            return Ok(TransactProofRoute {
                railgun_txid,
                permit: None,
            });
        };
        // Admission and the open run under the gate, so an invalid job is not
        // admitted and invalidation interrupts a pending open.
        let admission = self
            .effects
            .gate
            .dispatch::<_, _, Infallible>(async {
                match routing.scheduler.try_reserve(chain_id, railgun_txid) {
                    PoiSubmissionAdmission::Admitted(reservation) => {
                        reservation.open(routing).await.map_err(|error| {
                            debug!(
                                chain_id,
                                %error,
                                "PPOI route unavailable; transact proofs deferred"
                            );
                            None
                        })
                    }
                    PoiSubmissionAdmission::Deferred { until } => Err(until),
                }
            })
            .await;
        let until = match admission {
            Ok(permit) => {
                return Ok(TransactProofRoute {
                    railgun_txid,
                    permit: Some(permit),
                });
            }
            Err(WalletPrivateRemoteError::Remote(until)) => until,
            Err(WalletPrivateRemoteError::Stale(_)) => {
                return Err(TransactProofsDeferred { until: None });
            }
            Err(WalletPrivateRemoteError::Check(never)) => match never {},
        };
        if let Some(kind) = forced {
            let mut txids = self.forced_deferrals.txids();
            let recorded = txids.entry(railgun_txid).or_insert(kind);
            *recorded = (*recorded).max(kind);
        }
        Err(TransactProofsDeferred { until })
    }

    /// Unchanged without a route provider. With one, a random order that
    /// picks each next item with probability proportional to its `weight`,
    /// counted as at least 1.
    pub(crate) fn submission_order<T>(
        &self,
        mut items: Vec<T>,
        weight: impl Fn(&T) -> usize,
    ) -> Vec<T> {
        let Some(routing) = &self.routing else {
            return items;
        };
        let mut weights = items
            .iter()
            .map(|item| weight(item).max(1))
            .collect::<Vec<_>>();
        let mut ordered = Vec::with_capacity(items.len());
        while !weights.is_empty() {
            let mut pick = routing.scheduler.choose_index(weights.iter().sum());
            let mut index = 0;
            while pick >= weights[index] {
                pick -= weights[index];
                index += 1;
            }
            weights.swap_remove(index);
            ordered.push(items.swap_remove(index));
        }
        ordered
    }

    /// Unchanged without a route provider. With one, a uniform random order
    /// of the distinct keys, keeping each key's items together and in order.
    pub(crate) fn submission_order_by_key<T, K: Ord>(
        &self,
        items: Vec<T>,
        key: impl Fn(&T) -> K,
    ) -> Vec<T> {
        if self.routing.is_none() {
            return items;
        }
        let mut groups = BTreeMap::<K, Vec<T>>::new();
        for item in items {
            groups.entry(key(&item)).or_default().push(item);
        }
        self.submission_order(groups.into_values().collect(), |_| 1)
            .into_iter()
            .flatten()
            .collect()
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

    /// Hands the context off to the chain PPOI submitter. Returns once the
    /// submitter has recorded it, without waiting for the POI node.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn submit_single_commitment_proofs<Check, CheckFuture, CheckError>(
        &self,
        check_subject: Check,
        intent: PendingOutputPoiSubmitIntent,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), WalletPrivateRemoteError<PendingOutputPoiHandoffFailure, CheckError>>
    where
        Check: FnOnce() -> CheckFuture,
        CheckFuture: std::future::Future<Output = Result<bool, CheckError>>,
    {
        self.effects
            .run(check_subject, || {
                self.handoff.hand_off_single_commitment_proofs(
                    intent,
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

    /// Sends one transact proof of `route`'s transaction over that route.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn submit_transact_proof<Check, CheckFuture, CheckError>(
        &self,
        route: &TransactProofRoute,
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
        let submitter: &dyn PendingOutputPoiSubmitter = match &route.permit {
            Some(permit) => permit.submitter(),
            None => self.submit.as_ref(),
        };
        self.effects
            .run(check_subject, || {
                submitter.submit_transact_proof(
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
    /// `submit` serves transact proofs directly and, through
    /// `test_support::SubmitterHandoff`, the single-commitment handoffs.
    pub(crate) fn for_test(
        authority: WalletPrivateRemoteAuthority,
        status: Arc<dyn PoiStatusReader>,
        submit: Arc<dyn PendingOutputPoiSubmitter>,
    ) -> Self {
        let handoff = Arc::new(test_support::SubmitterHandoff(Arc::clone(&submit)));
        Self {
            effects: WalletPrivateRemoteEffects::new(authority),
            status,
            submit,
            handoff,
            routing: None,
            forced_deferrals: DeferredForcedSubmissions::default(),
        }
    }

    pub(crate) fn for_status(
        authority: WalletPrivateRemoteAuthority,
        status: Arc<dyn PoiStatusReader>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self::for_test(authority, status, unavailable)
    }

    pub(crate) fn for_submit(
        authority: WalletPrivateRemoteAuthority,
        submit: Arc<dyn PendingOutputPoiSubmitter>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self::for_test(authority, unavailable, submit)
    }

    /// Single-commitment handoffs go to `handoff`; status reads and transact
    /// proofs are unavailable.
    pub(crate) fn for_handoff(
        authority: WalletPrivateRemoteAuthority,
        handoff: Arc<dyn PendingOutputPoiHandoff>,
    ) -> Self {
        let unavailable = Arc::new(test_support::UnavailablePrivatePoiTransport);
        Self {
            effects: WalletPrivateRemoteEffects::new(authority),
            status: unavailable.clone(),
            submit: unavailable,
            handoff,
            routing: None,
            forced_deferrals: DeferredForcedSubmissions::default(),
        }
    }
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::wallet::{async_trait, is_missing_railgun_txid_error};

    pub(super) struct UnavailablePrivatePoiTransport;

    /// Test handoff over a recording or scripted submitter mock: each handoff
    /// is one single-commitment call, and a failed call becomes the handoff
    /// failure the chain submitter would report for it.
    pub(super) struct SubmitterHandoff(pub(super) Arc<dyn PendingOutputPoiSubmitter>);

    #[async_trait]
    impl PendingOutputPoiHandoff for SubmitterHandoff {
        #[allow(clippy::too_many_arguments)]
        async fn hand_off_single_commitment_proofs(
            &self,
            _intent: PendingOutputPoiSubmitIntent,
            txid_version: &str,
            chain_type: u8,
            chain_id: u64,
            context: SingleCommitmentProofContext,
            utxo_tree_out: u64,
            utxo_position_out: u64,
        ) -> Result<(), PendingOutputPoiHandoffFailure> {
            self.0
                .submit_single_commitment_proofs(
                    txid_version,
                    chain_type,
                    chain_id,
                    &context,
                    utxo_tree_out,
                    utxo_position_out,
                )
                .await
                .map_err(|error| PendingOutputPoiHandoffFailure {
                    missing_txid: is_missing_railgun_txid_error(&error),
                    summary: error.to_string(),
                })
        }
    }

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
