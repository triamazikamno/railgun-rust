//! Chain-owned sender for the single-commitment PPOI proofs of sent outputs.
//!
//! A wallet hands off send-ready contexts before broadcast. The driver learns
//! each output's position from finalized live rows or wallet handoffs and
//! sends independent of the active wallet. With a route provider it sends
//! each Railgun transaction's proofs over that transaction's isolated route,
//! as the shared submission scheduler admits it, and the transaction stays
//! admitted while any of its proofs waits or runs; otherwise it sends through
//! the wallets' shared POI client. State is memory-only and ends at chain
//! cancel or at each entry's TTL.

use std::collections::{HashMap, VecDeque, hash_map};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use alloy::primitives::{FixedBytes, U256};
use async_trait::async_trait;
use broadcaster_core::tree::normalize_tree_position;
use merkletree::tree::MerkleTreeUpdate;
use poi::error::PoiError;
use poi::poi::SingleCommitmentProofContext;
use railgun_wallet::scan::WalletScanInputRows;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{AbortHandle, JoinError, JoinHandle, JoinSet};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::{ChainPublicDataPlane, EVM_CHAIN_TYPE};
use crate::poi_submission::{
    PoiSubmissionAdmission, PoiSubmissionReservation, PoiSubmissionRouting,
};
use crate::types::GlobalPoiPolicy;
use crate::wallet::{PendingOutputPoiSubmitter, WalletPoiRuntime, is_missing_railgun_txid_error};

/// Bound of the command channel. Commands are answered after in-memory work
/// only, so the queue drains quickly.
const COMMAND_CHANNEL_CAPACITY: usize = 256;
/// Sends running at once; further sends wait in FIFO order, or for their
/// transaction's admission when routed.
const MAX_IN_FLIGHT_SENDS: usize = 4;
/// Lifetime of an entry after its latest prepare or handoff.
const ENTRY_TTL: Duration = Duration::from_mins(30);
const INITIAL_RETRY_BACKOFF: Duration = Duration::from_secs(15);
const MAX_RETRY_BACKOFF: Duration = Duration::from_mins(5);

/// Why the wallet hands a single-commitment context to the chain submitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingOutputPoiSubmitIntent {
    /// Pending-tip observation of the output; never overrides a finalized position.
    Tentative,
    /// First submission after the wallet's finalized observation.
    Missing,
    /// Resubmission after the wallet's retry window elapsed without validation.
    RetrySubmitted,
    /// User-forced resubmission.
    ForceMatching,
}

/// Failure reported to a handoff whose tuple is the entry's current tuple and
/// whose last completed attempt failed.
pub(crate) struct PendingOutputPoiHandoffFailure {
    /// Display text of the failed attempt's error, or of the handoff rejection.
    pub(crate) summary: String,
    /// Whether the POI node reported that it could not find the railgun TXID.
    pub(crate) missing_txid: bool,
}

impl fmt::Debug for PendingOutputPoiHandoffFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingOutputPoiHandoffFailure")
            .field("missing_txid", &self.missing_txid)
            .finish_non_exhaustive()
    }
}

impl PendingOutputPoiHandoffFailure {
    fn submitter_closed() -> Self {
        Self {
            summary: "chain PPOI submitter is not running".to_string(),
            missing_txid: false,
        }
    }
}

/// The chain submitter has stopped because the chain service is shutting down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainPoiSubmitterClosed;

/// Wallet-facing transport for single-commitment PPOI proofs.
///
/// Returns once the submitter has recorded the handoff; it never waits for
/// the POI node.
#[async_trait]
pub(crate) trait PendingOutputPoiHandoff: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn hand_off_single_commitment_proofs(
        &self,
        intent: PendingOutputPoiSubmitIntent,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PendingOutputPoiHandoffFailure>;
}

/// Cloneable handle to the chain's PPOI submitter driver.
#[derive(Clone)]
pub(crate) struct ChainPoiSubmitterHandle {
    commands: mpsc::Sender<Command>,
    pending: Arc<AtomicUsize>,
    /// The driver's routing, which wallets share for their transact proofs.
    routing: Option<PoiSubmissionRouting>,
}

impl ChainPoiSubmitterHandle {
    /// Inserts the contexts and returns once the driver has stored the new
    /// entry count. Fails only when the driver has stopped.
    pub(crate) async fn prepare(
        &self,
        contexts: Vec<SingleCommitmentProofContext>,
    ) -> Result<(), ChainPoiSubmitterClosed> {
        let (reply, done) = oneshot::channel();
        self.commands
            .send(Command::Prepare { contexts, reply })
            .await
            .map_err(|_| ChainPoiSubmitterClosed)?;
        done.await.map_err(|_| ChainPoiSubmitterClosed)
    }

    /// The chain's per-transaction PPOI routing, if it has a route provider.
    pub(crate) const fn submission_routing(&self) -> Option<&PoiSubmissionRouting> {
        self.routing.as_ref()
    }

    /// Number of entries the driver holds, as last stored by the driver.
    pub(crate) fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Reports the transact commitments of a finalized live batch. Costs one
    /// atomic load when nothing is pending.
    pub(crate) async fn observe(&self, rows: &WalletScanInputRows) {
        if self.pending_count() == 0 {
            return;
        }
        let outputs = rows
            .transact_commitments
            .iter()
            .map(|row| {
                let (tree, position) = normalize_tree_position(row.tree_number, row.tree_position);
                ObservedOutput {
                    commitment: FixedBytes::from(row.hash.to_be_bytes::<32>()),
                    output: OutputPosition {
                        tree: u64::from(tree),
                        position,
                    },
                }
            })
            .collect::<Vec<_>>();
        self.observe_outputs(outputs).await;
    }

    /// Reports the leaves a finalized forest install added. The caller gates
    /// on `pending_count`.
    pub(crate) async fn observe_forest_leaves(&self, leaves: Vec<MerkleTreeUpdate>) {
        let outputs = leaves
            .into_iter()
            .map(|leaf| ObservedOutput {
                commitment: FixedBytes::from(leaf.hash.to_be_bytes::<32>()),
                // Forest coordinates are already canonical.
                output: OutputPosition {
                    tree: u64::from(leaf.tree_number),
                    position: leaf.tree_position,
                },
            })
            .collect::<Vec<_>>();
        self.observe_outputs(outputs).await;
    }

    async fn observe_outputs(&self, outputs: Vec<ObservedOutput>) {
        if outputs.is_empty() {
            return;
        }
        // A closed channel means the chain is shutting down.
        let _ = self.commands.send(Command::Observe { outputs }).await;
    }

    /// A handle whose driver is gone: `prepare` fails at once and handoffs
    /// report the submitter as not running.
    #[cfg(test)]
    pub(crate) fn detached_for_test() -> Self {
        let (commands, _) = mpsc::channel(1);
        Self {
            commands,
            pending: Arc::default(),
            routing: None,
        }
    }

    /// Spawns a driver for `chain_id` that sends through `transport` and
    /// skips the corpus refresh.
    #[cfg(test)]
    pub(crate) fn spawn_for_test(
        chain_id: u64,
        transport: Arc<dyn PendingOutputPoiSubmitter>,
        cancel: CancellationToken,
    ) -> (Self, JoinHandle<()>) {
        let (handle, driver) = ChainPoiSubmitterDriver::unspawned_for_test(chain_id, transport);
        (handle, driver.spawn(cancel))
    }
}

#[async_trait]
impl PendingOutputPoiHandoff for ChainPoiSubmitterHandle {
    #[allow(clippy::too_many_arguments)]
    async fn hand_off_single_commitment_proofs(
        &self,
        intent: PendingOutputPoiSubmitIntent,
        txid_version: &str,
        chain_type: u8,
        chain_id: u64,
        context: SingleCommitmentProofContext,
        utxo_tree_out: u64,
        utxo_position_out: u64,
    ) -> Result<(), PendingOutputPoiHandoffFailure> {
        let (reply, done) = oneshot::channel();
        let handoff = Handoff {
            intent,
            matches_context: txid_version == context.txid_version,
            chain_type,
            chain_id,
            context,
            output: OutputPosition {
                tree: utxo_tree_out,
                position: utxo_position_out,
            },
        };
        if self
            .commands
            .send(Command::Handoff { handoff, reply })
            .await
            .is_err()
        {
            return Err(PendingOutputPoiHandoffFailure::submitter_closed());
        }
        done.await
            .unwrap_or_else(|_| Err(PendingOutputPoiHandoffFailure::submitter_closed()))
    }
}

/// The driver before it is spawned by `PreparedChainService::activate`.
pub(super) struct ChainPoiSubmitterDriver {
    commands: mpsc::Receiver<Command>,
    state: DriverState,
}

impl ChainPoiSubmitterDriver {
    /// Builds the chain's submitter over the proxied POI client wallets use,
    /// or over per-transaction routes when `routing` is set. The corpus
    /// refresh after a successful send runs only with indexed POI artifacts,
    /// where a local corpus exists.
    pub(super) fn for_chain(
        chain_id: u64,
        poi_policy: &GlobalPoiPolicy,
        http_client: &reqwest::Client,
        public_data_plane: &ChainPublicDataPlane,
        routing: Option<PoiSubmissionRouting>,
    ) -> (ChainPoiSubmitterHandle, Self) {
        let runtime = WalletPoiRuntime::from_policy(poi_policy, Some(http_client));
        let refresh_plane = runtime
            .is_indexed_artifacts()
            .then(|| public_data_plane.clone());
        Self::new(
            chain_id,
            Arc::new(runtime.public_client().clone()),
            refresh_plane,
            routing,
        )
    }

    fn new(
        chain_id: u64,
        transport: Arc<dyn PendingOutputPoiSubmitter>,
        public_data_plane: Option<ChainPublicDataPlane>,
        routing: Option<PoiSubmissionRouting>,
    ) -> (ChainPoiSubmitterHandle, Self) {
        let (commands_tx, commands) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let pending = Arc::new(AtomicUsize::new(0));
        let handle = ChainPoiSubmitterHandle {
            commands: commands_tx,
            pending: Arc::clone(&pending),
            routing: routing.clone(),
        };
        let driver = Self {
            commands,
            state: DriverState {
                chain_id,
                transport,
                route_changes: routing.as_ref().map(|routing| routing.scheduler.changed()),
                routing,
                admission_retry_at: None,
                public_data_plane,
                pending,
                entries: HashMap::new(),
                queue: VecDeque::new(),
                sends: JoinSet::new(),
                running: HashMap::new(),
                refresh: JoinSet::new(),
                refresh_again: false,
                next_attempt_id: 0,
            },
        };
        (handle, driver)
    }

    /// Builds a driver for `chain_id` that sends through `transport` and
    /// skips the corpus refresh, leaving the caller to spawn it.
    #[cfg(test)]
    pub(super) fn unspawned_for_test(
        chain_id: u64,
        transport: Arc<dyn PendingOutputPoiSubmitter>,
    ) -> (ChainPoiSubmitterHandle, Self) {
        Self::new(chain_id, transport, None, None)
    }

    /// Number of commands waiting for the driver.
    #[cfg(test)]
    pub(super) fn queued_commands_for_test(&self) -> usize {
        self.commands.len()
    }

    /// Spawns the driver. It stops at `cancel`, aborting and awaiting its
    /// sends and corpus refresh before the returned task completes.
    pub(super) fn spawn(self, cancel: CancellationToken) -> JoinHandle<()> {
        let Self {
            mut commands,
            mut state,
        } = self;
        tokio::spawn(async move {
            loop {
                let deadline = state.next_deadline();
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    command = commands.recv() => {
                        let Some(command) = command else { break };
                        state.handle_command(command);
                    }
                    Some(joined) = state.sends.join_next_with_id() => state.finish_send(joined),
                    Some(_) = state.refresh.join_next() => state.finish_refresh(),
                    () = route_released(state.route_changes.as_mut()) => {
                        state.start_queued_sends();
                    }
                    () = sleep_until_deadline(deadline) => state.handle_deadline(),
                }
            }
            drop(commands);
            state.sends.shutdown().await;
            state.refresh.shutdown().await;
        })
    }
}

async fn sleep_until_deadline(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Completes when the scheduler frees a route slot; never without routing.
async fn route_released(changes: Option<&mut watch::Receiver<()>>) {
    let Some(changes) = changes else {
        return std::future::pending().await;
    };
    if changes.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

enum Command {
    Prepare {
        contexts: Vec<SingleCommitmentProofContext>,
        reply: oneshot::Sender<()>,
    },
    Handoff {
        handoff: Handoff,
        reply: oneshot::Sender<Result<(), PendingOutputPoiHandoffFailure>>,
    },
    Observe {
        outputs: Vec<ObservedOutput>,
    },
}

struct Handoff {
    intent: PendingOutputPoiSubmitIntent,
    matches_context: bool,
    chain_type: u8,
    chain_id: u64,
    context: SingleCommitmentProofContext,
    output: OutputPosition,
}

struct ObservedOutput {
    commitment: FixedBytes<32>,
    output: OutputPosition,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct OutputPosition {
    tree: u64,
    position: u64,
}

/// Sorted list keys of a context's proofs.
type ListSet = Vec<FixedBytes<32>>;

fn list_set(context: &SingleCommitmentProofContext) -> ListSet {
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .keys()
        .copied()
        .collect()
}

struct Entry {
    context: Arc<SingleCommitmentProofContext>,
    lists: ListSet,
    placement: Option<Placement>,
    expires_at: Instant,
}

impl Entry {
    fn new(context: SingleCommitmentProofContext, expires_at: Instant) -> Self {
        Self {
            lists: list_set(&context),
            context: Arc::new(context),
            placement: None,
            expires_at,
        }
    }

    fn replace_context(&mut self, context: SingleCommitmentProofContext) {
        self.lists = list_set(&context);
        self.context = Arc::new(context);
    }

    /// Whether the current tuple is in flight or acknowledged.
    fn current_tuple_settled(&self) -> bool {
        self.placement.as_ref().is_some_and(|placement| {
            placement.in_flight(&self.lists) || placement.acked.contains(&self.lists)
        })
    }

    /// Moves the entry to a finalized position. A matching tentative position
    /// is marked finalized and loses the failure summary and backoff left by
    /// tentative attempts; its in-flight and ack state are kept. A matching
    /// finalized position is unchanged.
    fn place_finalized(&mut self, output: OutputPosition) {
        match self.placement.as_mut() {
            Some(placement) if placement.output == output => {
                if !placement.finalized {
                    placement.finalized = true;
                    placement.failure = None;
                    placement.backoff = None;
                }
            }
            _ => self.replace_placement(output, true),
        }
    }

    fn replace_placement(&mut self, output: OutputPosition, finalized: bool) {
        if let Some(attempt) = self
            .placement
            .take()
            .and_then(|placement| placement.attempt)
        {
            attempt.cancel();
        }
        self.placement = Some(Placement {
            output,
            finalized,
            attempt: None,
            acked: Vec::new(),
            failure: None,
            backoff: None,
        });
    }

    fn cancel_attempt(self) {
        if let Some(attempt) = self.placement.and_then(|placement| placement.attempt) {
            attempt.cancel();
        }
    }
}

/// State of the entry's current position; replaced wholesale when the
/// position changes.
struct Placement {
    output: OutputPosition,
    finalized: bool,
    attempt: Option<Attempt>,
    acked: Vec<ListSet>,
    /// Failure of the last completed attempt, with the lists it sent.
    failure: Option<(ListSet, PendingOutputPoiHandoffFailure)>,
    backoff: Option<Backoff>,
}

impl Placement {
    fn in_flight(&self, lists: &ListSet) -> bool {
        self.attempt
            .as_ref()
            .is_some_and(|attempt| &attempt.lists == lists)
    }
}

struct Attempt {
    id: u64,
    context: Arc<SingleCommitmentProofContext>,
    lists: ListSet,
    running: Option<AbortHandle>,
    /// While queued and routed, the transaction's live reservation, which
    /// keeps it admitted until this attempt starts, is cancelled or expires.
    /// The started send owns it instead.
    reservation: Option<PoiSubmissionReservation>,
}

impl Attempt {
    /// Aborts a running send. A queued one drops its reservation and is
    /// skipped when dequeued.
    fn cancel(self) {
        if let Some(running) = self.running {
            running.abort();
        }
    }
}

struct Backoff {
    next_delay: Duration,
    retry_at: Option<Instant>,
}

/// Railgun TXID of queued attempt `id` of `commitment`, or `None` once that
/// attempt was cancelled, superseded or started.
fn queued_txid(
    entries: &HashMap<FixedBytes<32>, Entry>,
    commitment: FixedBytes<32>,
    id: u64,
) -> Option<U256> {
    let attempt = entries
        .get(&commitment)?
        .placement
        .as_ref()?
        .attempt
        .as_ref()?;
    (attempt.id == id && attempt.running.is_none()).then_some(attempt.context.railgun_txid)
}

/// Queued attempt `id` of `commitment`, unless it was cancelled, superseded
/// or started.
fn queued_attempt_mut(
    entries: &mut HashMap<FixedBytes<32>, Entry>,
    commitment: FixedBytes<32>,
    id: u64,
) -> Option<&mut Attempt> {
    entries
        .get_mut(&commitment)?
        .placement
        .as_mut()?
        .attempt
        .as_mut()
        .filter(|attempt| attempt.id == id && attempt.running.is_none())
}

/// How a spawned send ended.
enum SendOutcome {
    Completed(Result<(), PoiError>),
    /// The transaction's route did not open; nothing was sent.
    RouteUnavailable,
}

struct DriverState {
    chain_id: u64,
    /// Shared client for every send when `routing` is `None`.
    transport: Arc<dyn PendingOutputPoiSubmitter>,
    routing: Option<PoiSubmissionRouting>,
    /// Marked when the scheduler frees a route slot; set with `routing`.
    route_changes: Option<watch::Receiver<()>>,
    /// When admission spacing ends after the scheduler deferred a send.
    admission_retry_at: Option<Instant>,
    public_data_plane: Option<ChainPublicDataPlane>,
    pending: Arc<AtomicUsize>,
    entries: HashMap<FixedBytes<32>, Entry>,
    /// Queued attempts, by commitment and attempt id.
    queue: VecDeque<(FixedBytes<32>, u64)>,
    sends: JoinSet<SendOutcome>,
    /// Commitment and attempt id of each spawned send.
    running: HashMap<tokio::task::Id, (FixedBytes<32>, u64)>,
    refresh: JoinSet<()>,
    refresh_again: bool,
    next_attempt_id: u64,
}

impl DriverState {
    fn store_pending(&self) {
        self.pending.store(self.entries.len(), Ordering::Release);
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .values()
            .flat_map(|entry| {
                let retry_at = entry
                    .placement
                    .as_ref()
                    .and_then(|placement| placement.backoff.as_ref())
                    .and_then(|backoff| backoff.retry_at);
                [Some(entry.expires_at), retry_at]
            })
            .flatten()
            .chain(self.admission_retry_at)
            .min()
    }

    fn handle_command(&mut self, command: Command) {
        match command {
            Command::Prepare { contexts, reply } => {
                let expires_at = Instant::now() + ENTRY_TTL;
                let prepared = contexts.len();
                for context in contexts {
                    match self.entries.get_mut(&context.commitment) {
                        Some(entry) => {
                            entry.replace_context(context);
                            entry.expires_at = expires_at;
                        }
                        None => {
                            self.entries
                                .insert(context.commitment, Entry::new(context, expires_at));
                        }
                    }
                }
                self.store_pending();
                debug!(
                    chain_id = self.chain_id,
                    contexts = prepared,
                    pending = self.entries.len(),
                    "chain PPOI contexts prepared"
                );
                let _ = reply.send(());
            }
            Command::Handoff { handoff, reply } => {
                let result = self.handle_handoff(handoff);
                self.store_pending();
                let _ = reply.send(result);
            }
            Command::Observe { outputs } => {
                let mut matched = 0_usize;
                let mut sends = 0_usize;
                for observed in outputs {
                    let Some(entry) = self.entries.get_mut(&observed.commitment) else {
                        continue;
                    };
                    matched += 1;
                    entry.place_finalized(observed.output);
                    if !entry.current_tuple_settled() {
                        sends += 1;
                        self.queue_send(observed.commitment);
                    }
                }
                // Started once the whole batch is queued, so that its first
                // transaction gets no head start in admission.
                if sends > 0 {
                    self.start_queued_sends();
                }
                self.store_pending();
                if matched > 0 {
                    debug!(
                        chain_id = self.chain_id,
                        matched, sends, "chain PPOI outputs observed"
                    );
                }
            }
        }
    }

    fn handle_handoff(&mut self, handoff: Handoff) -> Result<(), PendingOutputPoiHandoffFailure> {
        let Handoff {
            intent,
            matches_context,
            chain_type,
            chain_id,
            context,
            output,
        } = handoff;
        if !matches_context || chain_type != EVM_CHAIN_TYPE || chain_id != self.chain_id {
            debug!(
                chain_id = self.chain_id,
                ?intent,
                "chain PPOI handoff rejected; chain or TXID version mismatch"
            );
            return Err(PendingOutputPoiHandoffFailure {
                summary: "PPOI handoff does not match the chain submitter".to_string(),
                missing_txid: false,
            });
        }
        let commitment = context.commitment;
        let lists = list_set(&context);
        let expires_at = Instant::now() + ENTRY_TTL;
        let (entry, finalized) = match self.entries.entry(commitment) {
            hash_map::Entry::Occupied(occupied) => {
                let entry = occupied.into_mut();
                let finalized = entry
                    .placement
                    .as_ref()
                    .is_some_and(|placement| placement.finalized);
                // A tentative handoff after finalization changes nothing, including the context.
                if !(finalized && intent == PendingOutputPoiSubmitIntent::Tentative) {
                    entry.replace_context(context);
                }
                (entry, finalized)
            }
            hash_map::Entry::Vacant(vacant) => {
                (vacant.insert(Entry::new(context, expires_at)), false)
            }
        };
        entry.expires_at = expires_at;
        let send = match intent {
            PendingOutputPoiSubmitIntent::Tentative if finalized => false,
            PendingOutputPoiSubmitIntent::Tentative => {
                if entry
                    .placement
                    .as_ref()
                    .is_none_or(|placement| placement.output != output)
                {
                    entry.replace_placement(output, false);
                }
                !entry.current_tuple_settled()
            }
            PendingOutputPoiSubmitIntent::Missing => {
                entry.place_finalized(output);
                !entry.current_tuple_settled()
            }
            PendingOutputPoiSubmitIntent::RetrySubmitted
            | PendingOutputPoiSubmitIntent::ForceMatching => {
                entry.place_finalized(output);
                !entry
                    .placement
                    .as_ref()
                    .is_some_and(|placement| placement.in_flight(&entry.lists))
            }
        };
        if send {
            self.request_send(commitment);
        }
        let failure = self.entries.get(&commitment).and_then(|entry| {
            let placement = entry.placement.as_ref()?;
            let (failed_lists, failure) = placement.failure.as_ref()?;
            (placement.output == output && entry.lists == lists && *failed_lists == lists).then(
                || PendingOutputPoiHandoffFailure {
                    summary: failure.summary.clone(),
                    missing_txid: failure.missing_txid,
                },
            )
        });
        debug!(
            chain_id = self.chain_id,
            ?intent,
            send,
            reported_failure = failure.is_some(),
            "chain PPOI handoff recorded"
        );
        failure.map_or(Ok(()), Err)
    }

    /// Queues a send of the entry's current tuple and starts what may start.
    fn request_send(&mut self, commitment: FixedBytes<32>) {
        self.queue_send(commitment);
        self.start_queued_sends();
    }

    /// Queues a send of the entry's current tuple, replacing an attempt for
    /// other lists at the same position.
    fn queue_send(&mut self, commitment: FixedBytes<32>) {
        let Some(entry) = self.entries.get_mut(&commitment) else {
            return;
        };
        let Some(placement) = entry.placement.as_mut() else {
            return;
        };
        if placement.in_flight(&entry.lists) {
            return;
        }
        if let Some(previous) = placement.attempt.take() {
            previous.cancel();
        }
        let id = self.next_attempt_id;
        self.next_attempt_id = self.next_attempt_id.wrapping_add(1);
        placement.attempt = Some(Attempt {
            id,
            context: Arc::clone(&entry.context),
            lists: entry.lists.clone(),
            running: None,
            reservation: None,
        });
        if let Some(backoff) = placement.backoff.as_mut() {
            backoff.retry_at = None;
        }
        self.queue.push_back((commitment, id));
    }

    fn start_queued_sends(&mut self) {
        if let Some(routing) = self.routing.clone() {
            self.start_routed_sends(&routing);
            return;
        }
        while self.running.len() < MAX_IN_FLIGHT_SENDS {
            let Some((commitment, id)) = self.queue.pop_front() else {
                return;
            };
            self.spawn_send(commitment, id, None);
        }
    }

    /// Starts queued attempts that hold their transaction's reservation, then
    /// admits one uniformly random queued transaction at a time until the
    /// scheduler defers. Deferred attempts stay queued with their state
    /// untouched.
    fn start_routed_sends(&mut self, routing: &PoiSubmissionRouting) {
        self.admission_retry_at = None;
        let entries = &self.entries;
        self.queue
            .retain(|&(commitment, id)| queued_txid(entries, commitment, id).is_some());
        self.hold_live_reservations(routing);
        while self.running.len() < MAX_IN_FLIGHT_SENDS {
            let entries = &mut self.entries;
            let held = self
                .queue
                .iter()
                .enumerate()
                .find_map(|(index, &(commitment, id))| {
                    let attempt = queued_attempt_mut(entries, commitment, id)?;
                    Some((index, attempt.reservation.take()?))
                });
            if let Some((index, reservation)) = held {
                let Some((commitment, id)) = self.queue.remove(index) else {
                    return;
                };
                self.spawn_send(commitment, id, Some((routing.clone(), reservation)));
                continue;
            }
            let mut txids = Vec::<U256>::new();
            for &(commitment, id) in &self.queue {
                if let Some(txid) = queued_txid(&self.entries, commitment, id)
                    && !txids.contains(&txid)
                {
                    txids.push(txid);
                }
            }
            if txids.is_empty() {
                return;
            }
            let txid = txids[routing.scheduler.choose_index(txids.len())];
            match routing.scheduler.try_reserve(self.chain_id, txid) {
                PoiSubmissionAdmission::Admitted(admitted) => {
                    // Every queued attempt of the transaction takes the
                    // admission before any of them starts.
                    self.hold_live_reservations(routing);
                    drop(admitted);
                }
                PoiSubmissionAdmission::Deferred { until } => {
                    self.admission_retry_at = until;
                    return;
                }
            }
        }
    }

    /// Gives each queued attempt its transaction's live reservation, or
    /// none, so that a transaction with waiting attempts stays admitted after
    /// its running sends end, and a reservation whose open failed is dropped
    /// rather than reused.
    fn hold_live_reservations(&mut self, routing: &PoiSubmissionRouting) {
        for &(commitment, id) in &self.queue {
            if let Some(attempt) = queued_attempt_mut(&mut self.entries, commitment, id) {
                attempt.reservation = routing
                    .scheduler
                    .join(self.chain_id, attempt.context.railgun_txid);
            }
        }
    }

    /// Spawns queued attempt `id` of `commitment`, over the reservation's
    /// route when one is given; the send then owns the reservation. Skips a
    /// cancelled or superseded attempt.
    fn spawn_send(
        &mut self,
        commitment: FixedBytes<32>,
        id: u64,
        route: Option<(PoiSubmissionRouting, PoiSubmissionReservation)>,
    ) {
        let Some(placement) = self
            .entries
            .get_mut(&commitment)
            .and_then(|entry| entry.placement.as_mut())
        else {
            return;
        };
        let output = placement.output;
        let Some(attempt) = placement
            .attempt
            .as_mut()
            .filter(|attempt| attempt.id == id && attempt.running.is_none())
        else {
            return;
        };
        let transport = Arc::clone(&self.transport);
        let context = Arc::clone(&attempt.context);
        let chain_id = self.chain_id;
        let abort = self.sends.spawn(async move {
            // The permit, and with it the transaction's route, lives until
            // this send ends.
            let permit = match route {
                Some((routing, reservation)) => match reservation.open(&routing).await {
                    Ok(permit) => Some(permit),
                    Err(_) => return SendOutcome::RouteUnavailable,
                },
                None => None,
            };
            let submitter: &dyn PendingOutputPoiSubmitter = match &permit {
                Some(permit) => permit.submitter(),
                None => transport.as_ref(),
            };
            SendOutcome::Completed(
                submitter
                    .submit_single_commitment_proofs(
                        &context.txid_version,
                        EVM_CHAIN_TYPE,
                        chain_id,
                        &context,
                        output.tree,
                        output.position,
                    )
                    .await,
            )
        });
        self.running.insert(abort.id(), (commitment, id));
        attempt.running = Some(abort);
    }

    fn finish_send(&mut self, joined: Result<(tokio::task::Id, SendOutcome), JoinError>) {
        let (task_id, outcome) = match joined {
            Ok((task_id, outcome)) => (task_id, Some(outcome)),
            Err(err) => {
                if err.is_panic() {
                    warn!(chain_id = self.chain_id, "chain PPOI send task panicked");
                }
                (err.id(), None)
            }
        };
        if let Some((commitment, id)) = self.running.remove(&task_id) {
            match outcome {
                Some(SendOutcome::RouteUnavailable) => self.requeue_send(commitment, id),
                Some(SendOutcome::Completed(result)) => {
                    self.apply_send_result(commitment, id, Some(result));
                }
                None => self.apply_send_result(commitment, id, None),
            }
        }
        self.start_queued_sends();
    }

    /// Queues a started attempt again after its route failed to open,
    /// recording no failure or backoff.
    fn requeue_send(&mut self, commitment: FixedBytes<32>, id: u64) {
        let Some(attempt) = self
            .entries
            .get_mut(&commitment)
            .and_then(|entry| entry.placement.as_mut())
            .and_then(|placement| placement.attempt.as_mut())
            .filter(|attempt| attempt.id == id)
        else {
            return;
        };
        attempt.running = None;
        self.queue.push_back((commitment, id));
        debug!(
            chain_id = self.chain_id,
            "chain PPOI route unavailable; send deferred"
        );
    }

    /// Applies a completed attempt if it is still the entry's attempt. A
    /// cancelled or superseded attempt changes nothing.
    fn apply_send_result(
        &mut self,
        commitment: FixedBytes<32>,
        id: u64,
        result: Option<Result<(), PoiError>>,
    ) {
        let Some(entry) = self.entries.get_mut(&commitment) else {
            return;
        };
        let Some(placement) = entry.placement.as_mut() else {
            return;
        };
        let Some(attempt) = placement.attempt.take_if(|attempt| attempt.id == id) else {
            return;
        };
        let failure = match result {
            Some(Ok(())) => {
                if !placement.acked.contains(&attempt.lists) {
                    placement.acked.push(attempt.lists.clone());
                }
                if attempt.lists == entry.lists {
                    placement.failure = None;
                    placement.backoff = None;
                }
                debug!(chain_id = self.chain_id, "chain PPOI send accepted");
                self.request_refresh();
                return;
            }
            Some(Err(err)) => PendingOutputPoiHandoffFailure {
                missing_txid: is_missing_railgun_txid_error(&err),
                summary: err.to_string(),
            },
            None => PendingOutputPoiHandoffFailure {
                summary: "chain PPOI send task failed".to_string(),
                missing_txid: false,
            },
        };
        placement.failure = Some((attempt.lists, failure));
        let delay = placement
            .backoff
            .as_ref()
            .map_or(INITIAL_RETRY_BACKOFF, |backoff| backoff.next_delay);
        placement.backoff = Some(Backoff {
            next_delay: delay.saturating_mul(2).min(MAX_RETRY_BACKOFF),
            retry_at: Some(Instant::now() + delay),
        });
        debug!(
            chain_id = self.chain_id,
            retry_in_secs = delay.as_secs(),
            "chain PPOI send failed; retry scheduled"
        );
    }

    fn handle_deadline(&mut self) {
        let now = Instant::now();
        let expired = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(commitment, _)| *commitment)
            .collect::<Vec<_>>();
        for commitment in &expired {
            if let Some(entry) = self.entries.remove(commitment) {
                entry.cancel_attempt();
            }
        }
        if !expired.is_empty() {
            debug!(
                chain_id = self.chain_id,
                expired = expired.len(),
                pending = self.entries.len(),
                "chain PPOI entries expired"
            );
        }
        let due = self
            .entries
            .iter_mut()
            .filter_map(|(commitment, entry)| {
                let backoff = entry.placement.as_mut()?.backoff.as_mut()?;
                if backoff.retry_at.is_some_and(|retry_at| retry_at <= now) {
                    backoff.retry_at = None;
                    (!entry.current_tuple_settled()).then_some(*commitment)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        for commitment in due {
            self.queue_send(commitment);
        }
        // Also retries admission once its spacing ends.
        self.start_queued_sends();
        self.store_pending();
    }

    /// Starts one corpus refresh, or reruns it once the running one ends.
    /// Driver shutdown aborts and awaits the running refresh.
    fn request_refresh(&mut self) {
        let Some(public_data_plane) = self.public_data_plane.clone() else {
            return;
        };
        if !self.refresh.is_empty() {
            self.refresh_again = true;
            return;
        }
        let chain_id = self.chain_id;
        self.refresh.spawn(async move {
            let Ok(retry) = public_data_plane
                .retry_poi_artifact_cache_events(chain_id)
                .await
            else {
                debug!(chain_id, "chain PPOI corpus refresh admission skipped");
                return;
            };
            if retry.wait().await.is_err() {
                debug!(chain_id, "chain PPOI corpus refresh failed");
            }
        });
    }

    fn finish_refresh(&mut self) {
        if std::mem::take(&mut self.refresh_again) {
            self.request_refresh();
        }
    }
}

/// Recording transport for submitter tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use alloy::primitives::FixedBytes;
    use async_trait::async_trait;
    use poi::error::{PoiError, PoiRpcError};
    use poi::poi::SingleCommitmentProofContext;

    use crate::wallet::PendingOutputPoiSubmitter;

    /// One single-commitment send seen by the transport.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct RecordedSend {
        pub(crate) commitment: FixedBytes<32>,
        pub(crate) tree: u64,
        pub(crate) position: u64,
        pub(crate) lists: Vec<FixedBytes<32>>,
    }

    /// Scripted result of one send; unscripted sends succeed.
    pub(crate) enum ScriptedSend {
        /// Fails with a JSON-RPC error carrying this message.
        Fail(&'static str),
        /// Never completes.
        Stall,
    }

    #[derive(Default)]
    pub(crate) struct RecordingPoiTransport {
        sends: Mutex<Vec<RecordedSend>>,
        transact_sends: Mutex<Vec<(u64, FixedBytes<32>)>>,
        script: Mutex<VecDeque<ScriptedSend>>,
    }

    impl RecordingPoiTransport {
        pub(crate) fn script(&self, send: ScriptedSend) {
            self.script.lock().expect("script lock").push_back(send);
        }

        pub(crate) fn sends(&self) -> Vec<RecordedSend> {
            self.sends.lock().expect("sends lock").clone()
        }

        /// Transact proofs sent, as TXID merkleroot index and list key.
        pub(crate) fn transact_sends(&self) -> Vec<(u64, FixedBytes<32>)> {
            self.transact_sends.lock().expect("sends lock").clone()
        }
    }

    #[async_trait]
    impl PendingOutputPoiSubmitter for RecordingPoiTransport {
        async fn submit_single_commitment_proofs(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            context: &SingleCommitmentProofContext,
            utxo_tree_out: u64,
            utxo_position_out: u64,
        ) -> Result<(), PoiError> {
            self.sends.lock().expect("sends lock").push(RecordedSend {
                commitment: context.commitment,
                tree: utxo_tree_out,
                position: utxo_position_out,
                lists: context
                    .pre_transaction_pois_per_txid_leaf_per_list
                    .keys()
                    .copied()
                    .collect(),
            });
            let scripted = self.script.lock().expect("script lock").pop_front();
            match scripted {
                None => Ok(()),
                Some(ScriptedSend::Fail(message)) => Err(PoiError::RpcRequest {
                    source: PoiRpcError::JsonRpc {
                        code: -32000,
                        message: message.to_string(),
                        data: None,
                    },
                }),
                Some(ScriptedSend::Stall) => std::future::pending().await,
            }
        }

        async fn submit_transact_proof(
            &self,
            _txid_version: &str,
            _chain_type: u8,
            _chain_id: u64,
            list_key: &FixedBytes<32>,
            txid_merkleroot_index: u64,
            _poi: &broadcaster_core::transact::PreTxPoi,
        ) -> Result<(), PoiError> {
            self.transact_sends
                .lock()
                .expect("sends lock")
                .push((txid_merkleroot_index, *list_key));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use alloy::primitives::{FixedBytes, U256};
    use broadcaster_core::transact::DEFAULT_TXID_VERSION;
    use poi::poi::SingleCommitmentProofContext;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;

    use super::test_support::{RecordedSend, RecordingPoiTransport, ScriptedSend};
    use super::{
        ChainPoiSubmitterDriver, ChainPoiSubmitterHandle, EVM_CHAIN_TYPE, INITIAL_RETRY_BACKOFF,
        ObservedOutput, OutputPosition, PendingOutputPoiHandoff, PendingOutputPoiHandoffFailure,
        PendingOutputPoiSubmitIntent,
    };
    use crate::poi_submission::test_support::{RecordingRoutes, seeded_scheduler};
    use crate::poi_submission::{MAX_ADMISSION_GAP, MIN_ADMISSION_GAP, PoiSubmissionAdmission};
    use crate::wallet::PendingOutputPoiSubmitter;

    const CHAIN_ID: u64 = 1;
    const COMMITMENT: FixedBytes<32> = FixedBytes::new([0xc1; 32]);
    const LIST: FixedBytes<32> = FixedBytes::new([0x1a; 32]);

    struct Harness {
        handle: ChainPoiSubmitterHandle,
        transport: Arc<RecordingPoiTransport>,
        routes: Arc<RecordingRoutes>,
        cancel: CancellationToken,
        driver: JoinHandle<()>,
    }

    impl Harness {
        fn spawn() -> Self {
            Self::spawn_with(None)
        }

        /// Sends over per-TXID routes admitted by a scheduler seeded with `seed`.
        fn spawn_routed(seed: u64) -> Self {
            Self::spawn_with(Some(seed))
        }

        fn spawn_with(seed: Option<u64>) -> Self {
            let transport = Arc::new(RecordingPoiTransport::default());
            let routes = RecordingRoutes::new();
            let cancel = CancellationToken::new();
            let (handle, driver) = ChainPoiSubmitterDriver::new(
                CHAIN_ID,
                Arc::clone(&transport) as Arc<dyn PendingOutputPoiSubmitter>,
                None,
                seed.map(|seed| routes.routing(seeded_scheduler(seed))),
            );
            Self {
                handle,
                transport,
                routes,
                driver: driver.spawn(cancel.clone()),
                cancel,
            }
        }

        async fn prepare(&self) {
            self.prepare_contexts(vec![context()]).await;
        }

        async fn prepare_contexts(&self, contexts: Vec<SingleCommitmentProofContext>) {
            self.handle.prepare(contexts).await.expect("driver running");
        }

        async fn observe(&self, position: u64) {
            self.observe_at(&[(COMMITMENT, position)]).await;
        }

        /// Reports one finalized batch of `(commitment, position)` outputs.
        async fn observe_at(&self, outputs: &[(FixedBytes<32>, u64)]) {
            self.handle
                .observe_outputs(
                    outputs
                        .iter()
                        .map(|&(commitment, position)| ObservedOutput {
                            commitment,
                            output: OutputPosition { tree: 0, position },
                        })
                        .collect(),
                )
                .await;
            self.settle().await;
        }

        async fn hand_off(
            &self,
            intent: PendingOutputPoiSubmitIntent,
            position: u64,
        ) -> Result<(), PendingOutputPoiHandoffFailure> {
            self.hand_off_context(intent, context(), position).await
        }

        async fn hand_off_context(
            &self,
            intent: PendingOutputPoiSubmitIntent,
            context: SingleCommitmentProofContext,
            position: u64,
        ) -> Result<(), PendingOutputPoiHandoffFailure> {
            let result = self
                .handle
                .hand_off_single_commitment_proofs(
                    intent,
                    DEFAULT_TXID_VERSION,
                    EVM_CHAIN_TYPE,
                    CHAIN_ID,
                    context,
                    0,
                    position,
                )
                .await;
            self.settle().await;
            result
        }

        /// Waits until the driver has handled every earlier command and its
        /// spawned sends have run.
        async fn settle(&self) {
            self.handle
                .prepare(Vec::new())
                .await
                .expect("driver running");
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        }

        fn positions(&self) -> Vec<u64> {
            self.transport
                .sends()
                .iter()
                .map(|send| send.position)
                .collect()
        }

        /// Commitments sent over each opened route, in opening order.
        fn routed_commitments(&self) -> Vec<Vec<FixedBytes<32>>> {
            self.routes
                .routes()
                .iter()
                .map(|route| route.sends().iter().map(|send| send.commitment).collect())
                .collect()
        }

        async fn stop(self) {
            self.cancel.cancel();
            self.driver.await.expect("driver exits");
            assert!(
                self.transport.transact_sends().is_empty(),
                "the chain submitter never sends transact proofs"
            );
        }
    }

    fn context() -> SingleCommitmentProofContext {
        context_for(COMMITMENT, 7)
    }

    fn context_for(commitment: FixedBytes<32>, txid: u64) -> SingleCommitmentProofContext {
        SingleCommitmentProofContext {
            txid_version: DEFAULT_TXID_VERSION.to_string(),
            railgun_txid: U256::from(txid),
            utxo_tree_in: 0,
            commitment,
            npk: FixedBytes::new([0x22; 32]),
            pre_transaction_pois_per_txid_leaf_per_list: BTreeMap::from([(LIST, BTreeMap::new())]),
        }
    }

    #[tokio::test]
    async fn observation_sends_prepared_tuple_once() {
        let harness = Harness::spawn();
        harness.prepare().await;

        harness.observe(5).await;
        harness.observe(5).await;

        assert_eq!(
            harness.transport.sends(),
            vec![RecordedSend {
                commitment: COMMITMENT,
                tree: 0,
                position: 5,
                lists: vec![LIST],
            }]
        );
        harness.stop().await;
    }

    #[tokio::test]
    async fn finalized_position_confirms_or_replaces_tentative_one() {
        let harness = Harness::spawn();
        harness.prepare().await;

        let tentative = harness
            .hand_off(PendingOutputPoiSubmitIntent::Tentative, 5)
            .await;
        harness.observe(5).await;
        assert!(tentative.is_ok());
        assert_eq!(harness.positions(), vec![5], "same position sends once");

        harness.observe(6).await;
        let missing = harness
            .hand_off(PendingOutputPoiSubmitIntent::Missing, 7)
            .await;
        assert!(missing.is_ok());
        assert_eq!(harness.positions(), vec![5, 6, 7]);
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn late_tentative_handoff_keeps_finalized_retry() {
        let harness = Harness::spawn();
        harness.prepare().await;
        harness.transport.script(ScriptedSend::Fail("unavailable"));

        harness.observe(5).await;
        let tentative = harness
            .hand_off(PendingOutputPoiSubmitIntent::Tentative, 9)
            .await;
        assert!(tentative.is_ok());
        assert_eq!(
            harness.positions(),
            vec![5],
            "no send for the tentative position"
        );

        tokio::time::advance(Duration::from_secs(15)).await;
        harness.settle().await;
        assert_eq!(
            harness.positions(),
            vec![5, 5],
            "retry targets the finalized position"
        );
        harness.stop().await;
    }

    #[tokio::test]
    async fn retry_intents_resend_acked_tuple_unless_in_flight() {
        let harness = Harness::spawn();
        harness.prepare().await;
        harness.observe(5).await;

        harness
            .hand_off(PendingOutputPoiSubmitIntent::RetrySubmitted, 5)
            .await
            .expect("retry handoff");
        harness.transport.script(ScriptedSend::Stall);
        harness
            .hand_off(PendingOutputPoiSubmitIntent::ForceMatching, 5)
            .await
            .expect("forced handoff");
        assert_eq!(harness.positions(), vec![5, 5, 5], "acked tuple resent");

        harness
            .hand_off(PendingOutputPoiSubmitIntent::RetrySubmitted, 5)
            .await
            .expect("retry handoff while in flight");
        harness
            .hand_off(PendingOutputPoiSubmitIntent::ForceMatching, 5)
            .await
            .expect("forced handoff while in flight");
        assert_eq!(
            harness.positions(),
            vec![5, 5, 5],
            "no duplicate in-flight send"
        );
        harness.stop().await;
    }

    #[tokio::test]
    async fn handoff_for_failed_current_tuple_reports_failure_and_retries() {
        let harness = Harness::spawn();
        harness.prepare().await;
        harness
            .transport
            .script(ScriptedSend::Fail("Could not find railgun TXID"));
        harness.observe(5).await;

        let failure = harness
            .hand_off(PendingOutputPoiSubmitIntent::Missing, 5)
            .await
            .expect_err("last attempt failed");

        assert!(failure.missing_txid);
        assert_ne!(failure.summary, "");
        assert_eq!(
            harness.positions(),
            vec![5, 5],
            "the handoff retries the tuple"
        );
        harness.stop().await;
    }

    #[tokio::test]
    async fn tentative_failure_is_not_reported_after_finalization() {
        let harness = Harness::spawn();
        harness.prepare().await;
        harness
            .transport
            .script(ScriptedSend::Fail("Could not find railgun TXID"));
        harness.transport.script(ScriptedSend::Stall);

        harness
            .hand_off(PendingOutputPoiSubmitIntent::Tentative, 5)
            .await
            .expect("tentative handoff");
        harness.observe(5).await;
        harness
            .hand_off(PendingOutputPoiSubmitIntent::Missing, 5)
            .await
            .expect("tentative failure is not reported at the finalized position");

        assert_eq!(harness.positions(), vec![5, 5]);
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn entry_expires_after_latest_handoff() {
        let harness = Harness::spawn();
        harness.prepare().await;
        tokio::time::advance(Duration::from_mins(10)).await;
        harness
            .hand_off(PendingOutputPoiSubmitIntent::Tentative, 5)
            .await
            .expect("tentative handoff");
        tokio::time::advance(Duration::from_mins(10)).await;
        harness
            .hand_off(PendingOutputPoiSubmitIntent::Missing, 5)
            .await
            .expect("missing handoff");

        tokio::time::advance(Duration::from_mins(30) - Duration::from_secs(1)).await;
        harness.settle().await;
        assert_eq!(harness.handle.pending_count(), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        harness.settle().await;
        assert_eq!(harness.handle.pending_count(), 0);
        harness.stop().await;
    }

    fn commitment(byte: u8) -> FixedBytes<32> {
        FixedBytes::new([byte; 32])
    }

    #[tokio::test(start_paused = true)]
    async fn routed_batch_admits_a_random_txid_first_and_each_next_after_a_gap() {
        // The driver's first draw picks among the batch's three TXIDs.
        let (seed, picked) = (0..64)
            .map(|seed| (seed, seeded_scheduler(seed).choose_index(3)))
            .find(|&(_, picked)| picked != 0)
            .expect("a seed that does not pick the queue head");
        let harness = Harness::spawn_routed(seed);
        let outputs = [(commitment(1), 1), (commitment(2), 2), (commitment(3), 3)];
        harness
            .prepare_contexts(
                outputs
                    .map(|(commitment, txid)| context_for(commitment, txid))
                    .into(),
            )
            .await;

        harness.observe_at(&outputs).await;
        let first = vec![vec![outputs[picked].0]];
        assert_eq!(harness.routed_commitments(), first);

        tokio::time::advance(MIN_ADMISSION_GAP.saturating_sub(Duration::from_secs(1))).await;
        harness.settle().await;
        assert_eq!(harness.routed_commitments(), first, "spacing holds");

        for routes in 2..=3 {
            tokio::time::advance(MAX_ADMISSION_GAP).await;
            harness.settle().await;
            assert_eq!(
                harness.routed_commitments().len(),
                routes,
                "one more TXID after each gap"
            );
        }
        let mut admitted = harness.routed_commitments();
        admitted.sort();
        assert_eq!(
            admitted,
            outputs.map(|(commitment, _)| vec![commitment]),
            "every TXID is admitted over its own route"
        );
        harness.stop().await;
    }

    /// Each route's commitments sorted, routes in commitment order.
    fn sorted_routes(harness: &Harness) -> Vec<Vec<FixedBytes<32>>> {
        let mut routed = harness.routed_commitments();
        for route in &mut routed {
            route.sort();
        }
        routed.sort();
        routed
    }

    /// Releases stalled route opens and lets every send they unblock end
    /// before the driver handles any of those ends.
    async fn release_opens(harness: &Harness) {
        harness.routes.set_open_gate(true);
        tokio::task::yield_now().await;
        harness.settle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn outputs_of_one_txid_share_one_admission_and_route() {
        let harness = Harness::spawn_routed(0);
        // One more output than send slots.
        let outputs = (1..=5)
            .map(|byte| (commitment(byte), u64::from(byte)))
            .collect::<Vec<_>>();
        harness
            .prepare_contexts(
                outputs
                    .iter()
                    .map(|&(commitment, _)| context_for(commitment, 7))
                    .collect(),
            )
            .await;
        harness.routes.set_open_gate(false);

        harness.observe_at(&outputs).await;
        assert_eq!(
            harness.routes.opens(),
            1,
            "later sends join the stalled open"
        );
        release_opens(&harness).await;

        assert_eq!(
            sorted_routes(&harness),
            vec![
                outputs
                    .iter()
                    .map(|&(commitment, _)| commitment)
                    .collect::<Vec<_>>()
            ],
            "the waiting output keeps the admission after the others end"
        );
        assert_eq!(harness.routes.opens(), 1);
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn output_queued_behind_other_txids_keeps_its_route() {
        let harness = Harness::spawn_routed(0);
        let (first, later) = (commitment(1), commitment(2));
        let others = [commitment(3), commitment(4), commitment(5)];
        harness
            .prepare_contexts(
                [context_for(first, 1), context_for(later, 1)]
                    .into_iter()
                    .chain(others.map(|commitment| context_for(commitment, 2)))
                    .collect(),
            )
            .await;
        harness.routes.set_open_gate(false);
        harness.observe_at(&[(first, 1)]).await;
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        harness
            .observe_at(&others.map(|commitment| (commitment, 3)))
            .await;

        // Every send slot is taken, so the later output waits.
        harness.observe_at(&[(later, 2)]).await;
        assert_eq!(harness.routes.opens(), 2);
        release_opens(&harness).await;

        assert_eq!(
            sorted_routes(&harness),
            vec![vec![first, later], others.to_vec()],
            "the later output needs no new admission"
        );
        assert_eq!(harness.routes.opens(), 2);
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn queued_output_holds_its_admission_until_it_expires() {
        let harness = Harness::spawn_routed(0);
        let scheduler = Arc::clone(
            &harness
                .handle
                .submission_routing()
                .expect("routed")
                .scheduler,
        );
        let queued = commitment(1);
        let busy = (2..=5).map(commitment).collect::<Vec<_>>();
        harness.prepare_contexts(vec![context_for(queued, 1)]).await;
        tokio::time::advance(Duration::from_mins(1)).await;
        harness
            .prepare_contexts(
                busy.iter()
                    .map(|&commitment| context_for(commitment, 2))
                    .collect(),
            )
            .await;
        harness.routes.set_open_gate(false);
        harness
            .observe_at(
                &busy
                    .iter()
                    .map(|&commitment| (commitment, 2))
                    .collect::<Vec<_>>(),
            )
            .await;
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        let PoiSubmissionAdmission::Admitted(admitted) =
            scheduler.try_reserve(CHAIN_ID, U256::from(1))
        else {
            panic!("TXID 1 is admitted");
        };

        // Every send slot is taken, so the output waits.
        harness.observe_at(&[(queued, 1)]).await;
        drop(admitted);
        assert!(
            scheduler.join(CHAIN_ID, U256::from(1)).is_some(),
            "the waiting output holds the admission"
        );

        // The queued output's entry expires a minute before the others.
        tokio::time::advance(Duration::from_mins(27)).await;
        harness.settle().await;
        assert_eq!(harness.handle.pending_count(), busy.len());
        assert!(scheduler.join(CHAIN_ID, U256::from(1)).is_none());
        assert!(
            matches!(
                scheduler.try_reserve(CHAIN_ID, U256::from(3)),
                PoiSubmissionAdmission::Admitted(_)
            ),
            "the expired output frees its route slot"
        );
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn deferred_txid_keeps_its_attempt_and_reports_no_failure() {
        let harness = Harness::spawn_routed(0);
        let (first, second) = (commitment(1), commitment(2));
        harness
            .prepare_contexts(vec![context_for(first, 1), context_for(second, 2)])
            .await;
        harness
            .hand_off_context(
                PendingOutputPoiSubmitIntent::Missing,
                context_for(first, 1),
                1,
            )
            .await
            .expect("admitted");
        harness
            .hand_off_context(
                PendingOutputPoiSubmitIntent::Missing,
                context_for(second, 2),
                2,
            )
            .await
            .expect("a deferral is not a failure");

        // A failure would schedule a resend after this backoff, inside the gap.
        tokio::time::advance(INITIAL_RETRY_BACKOFF).await;
        harness.settle().await;
        harness
            .hand_off_context(
                PendingOutputPoiSubmitIntent::Missing,
                context_for(second, 2),
                2,
            )
            .await
            .expect("still no failure while deferred");
        assert_eq!(harness.routed_commitments(), vec![vec![first]]);

        tokio::time::advance(MAX_ADMISSION_GAP).await;
        harness.settle().await;
        assert_eq!(
            harness.routed_commitments(),
            vec![vec![first], vec![second]],
            "the queued attempt sends once"
        );
        harness.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn failed_route_open_defers_and_never_sends() {
        let harness = Harness::spawn_routed(0);
        harness.routes.fail_opens(true);
        // One more output than send slots, so one waits through the failure.
        let outputs = (1..=4)
            .map(|byte| (commitment(byte), u64::from(byte)))
            .chain([(COMMITMENT, 5)])
            .collect::<Vec<_>>();
        harness
            .prepare_contexts(
                outputs
                    .iter()
                    .map(|&(commitment, _)| context_for(commitment, 7))
                    .collect(),
            )
            .await;

        harness.observe_at(&outputs).await;
        harness
            .hand_off(PendingOutputPoiSubmitIntent::Missing, 5)
            .await
            .expect("a failed route open is not a send failure");
        assert_eq!(harness.routes.opens(), 1, "no output bypasses admission");
        assert_eq!(harness.routed_commitments(), [] as [Vec<FixedBytes<32>>; 0]);
        assert!(
            harness.transport.sends().is_empty(),
            "no shared-client fallback"
        );

        harness.routes.fail_opens(false);
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        harness.settle().await;
        let mut sent = outputs
            .iter()
            .map(|&(commitment, _)| commitment)
            .collect::<Vec<_>>();
        sent.sort();
        assert_eq!(
            sorted_routes(&harness),
            vec![sent],
            "every output goes over one freshly admitted route"
        );
        assert_eq!(harness.routes.opens(), 2);
        harness.stop().await;
    }
}
