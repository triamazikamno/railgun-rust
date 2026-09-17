//! Chain-owned transport for prepared PPOI submissions. Wallets retain encrypted
//! recovery state, but neither a wallet actor nor its cancellation token owns a send.
use alloy::primitives::{Address, FixedBytes};
use alloy::sol_types::SolEvent;
use alloy_rpc_types_eth::Log;
use broadcaster_core::contracts::railgun::Transact;
use broadcaster_core::transact::PreTxPoi;
use local_db::PendingOutputPoiContextRecord;
use poi::error::PoiError;
use poi::poi::SingleCommitmentProofContext;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::wallet::PendingOutputPoiSubmitter;

const RETRY_INTERVAL: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOB_TIMEOUT: Duration = Duration::from_mins(30);
// Match the wallet's automatic retry window; explicit recovery can clear successes.
const SUCCESS_TTL: Duration = Duration::from_mins(5);

#[derive(Clone)]
enum Submission {
    Single {
        context: SingleCommitmentProofContext,
        tree: u64,
        position: u64,
    },
    Transact {
        version: String,
        list: FixedBytes<32>,
        index: u64,
        proof: Box<PreTxPoi>,
    },
}

impl Submission {
    fn key(&self) -> Vec<u8> {
        // Include the payload as well as the output location. A reorg or a newly
        // generated proof must never reuse an acknowledgement for an older request.
        match self {
            Self::Single {
                context,
                tree,
                position,
            } => rmp_serde::to_vec(&(
                0_u8,
                &context.txid_version,
                context.railgun_txid,
                context.utxo_tree_in,
                context.commitment,
                context.npk,
                tree,
                position,
                &context.pre_transaction_pois_per_txid_leaf_per_list,
            )),
            Self::Transact {
                version,
                list,
                index,
                proof,
            } => rmp_serde::to_vec(&(1_u8, version, list, index, proof)),
        }
        .expect("PPOI submission contains only serializable protocol fields")
    }

    async fn send(
        &self,
        client: &dyn PendingOutputPoiSubmitter,
        chain_id: u64,
    ) -> Result<(), PoiError> {
        match self {
            Self::Single {
                context,
                tree,
                position,
            } => {
                client
                    .submit_single_commitment_proofs(
                        &context.txid_version,
                        0,
                        chain_id,
                        context,
                        *tree,
                        *position,
                    )
                    .await
            }
            Self::Transact {
                version,
                list,
                index,
                proof,
            } => {
                client
                    .submit_transact_proof(version, 0, chain_id, list, *index, proof)
                    .await
            }
        }
    }
}

#[derive(Clone, Copy)]
enum SubmissionFailure {
    Cancelled,
    TimedOut,
}

impl SubmissionFailure {
    const fn into_error(self) -> PoiError {
        match self {
            Self::Cancelled => PoiError::SubmissionCancelled,
            Self::TimedOut => PoiError::SubmissionTimedOut,
        }
    }
}

type SubmissionResult = Result<(), SubmissionFailure>;

#[derive(Clone)]
enum Status {
    Pending,
    Complete(SubmissionResult, Instant),
}

struct Job {
    result: watch::Receiver<Status>,
    location: Option<(FixedBytes<32>, u64, u64)>,
    task: JoinHandle<()>,
}

impl Drop for Job {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct State {
    prepared: HashMap<FixedBytes<32>, (SingleCommitmentProofContext, Instant)>,
    jobs: HashMap<Vec<u8>, Job>,
}

impl State {
    fn prune(&mut self) {
        self.prepared
            .retain(|_, (_, created)| created.elapsed() < JOB_TIMEOUT);
        self.jobs.retain(|_, job| match &*job.result.borrow() {
            Status::Pending => !job.task.is_finished(),
            Status::Complete(Ok(()), completed) => completed.elapsed() < SUCCESS_TTL,
            Status::Complete(Err(_), _) => false,
        });
    }
}

pub(crate) struct ChainPoiSubmitter {
    chain_id: u64,
    contract: Address,
    client: Arc<dyn PendingOutputPoiSubmitter>,
    cancel: CancellationToken,
    state: Mutex<State>,
}

impl std::fmt::Debug for ChainPoiSubmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainPoiSubmitter")
            .field("chain_id", &self.chain_id)
            .finish_non_exhaustive()
    }
}

impl ChainPoiSubmitter {
    pub(crate) fn new(
        chain_id: u64,
        contract: Address,
        client: Arc<dyn PendingOutputPoiSubmitter>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            chain_id,
            contract,
            client,
            cancel,
            state: Mutex::default(),
        }
    }

    /// Called inside the actor's durable context commit, before acknowledging it.
    /// These proofs alone are sufficient for transport; no wallet keys are retained.
    pub(crate) fn retain(&self, records: &[PendingOutputPoiContextRecord]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune();
        if self.cancel.is_cancelled() {
            return;
        }
        for record in records
            .iter()
            .filter(|record| record.chain_id == self.chain_id)
        {
            state
                .prepared
                .entry(record.output_commitment)
                .or_insert_with(|| {
                    (
                        SingleCommitmentProofContext {
                            txid_version: record.txid_version.clone(),
                            railgun_txid: record.railgun_txid,
                            utxo_tree_in: record.utxo_tree_in,
                            commitment: record.output_commitment,
                            npk: record.output_npk,
                            pre_transaction_pois_per_txid_leaf_per_list: record
                                .retain_poi_lists(&record.required_poi_list_keys),
                        },
                        Instant::now(),
                    )
                });
        }
    }

    /// Consume the chain's existing confirmed public logs, never transaction-specific RPCs.
    pub(crate) fn observe_logs(&self, logs: &[Log]) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prune();
        for log in logs {
            if log.removed
                || log.address() != self.contract
                || log.topic0() != Some(&Transact::SIGNATURE_HASH)
            {
                continue;
            }
            let Ok(event) = Transact::decode_log(&log.inner) else {
                continue;
            };
            let event = event.data;
            if event.hash.len() != event.ciphertext.len() {
                continue;
            }
            let (Ok(tree), Ok(start)) = (
                u64::try_from(event.treeNumber),
                u64::try_from(event.startPosition),
            ) else {
                continue;
            };
            for (offset, commitment) in event.hash.into_iter().enumerate() {
                let Some(position) = u64::try_from(offset)
                    .ok()
                    .and_then(|offset| start.checked_add(offset))
                else {
                    continue;
                };
                let Some((context, _)) = state.prepared.get(&commitment) else {
                    continue;
                };
                let context = context.clone();
                // A confirmed location supersedes any tentative/reorged location.
                // Cancelling the old transport also wakes any wallet waiting on it.
                state.jobs.retain(|_, job| {
                    job.location.is_none_or(|(output, old_tree, old_position)| {
                        output != commitment || old_tree == tree && old_position == position
                    })
                });
                for request in single_submissions(&context, tree, position) {
                    self.enqueue(&mut state, request);
                }
            }
        }
    }

    fn enqueue(&self, state: &mut State, request: Submission) -> watch::Receiver<Status> {
        let key = request.key();
        if let Some(job) = state.jobs.get(&key) {
            return job.result.clone();
        }
        let location = match &request {
            Submission::Single {
                context,
                tree,
                position,
            } => Some((context.commitment, *tree, *position)),
            Submission::Transact { .. } => None,
        };
        let (result_tx, result) = watch::channel(Status::Pending);
        let client = Arc::clone(&self.client);
        let cancel = self.cancel.clone();
        let chain_id = self.chain_id;
        let task = tokio::spawn(async move {
            let run = async {
                loop {
                    match tokio::time::timeout(
                        REQUEST_TIMEOUT,
                        request.send(client.as_ref(), chain_id),
                    )
                    .await
                    {
                        Ok(Ok(())) => return Ok(()),
                        Ok(Err(error)) => {
                            tracing::warn!(chain_id, %error, "chain PPOI submission failed; retrying");
                        }
                        Err(_) => {
                            tracing::warn!(chain_id, "chain PPOI submission timed out; retrying");
                        }
                    }
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            };
            let outcome = tokio::select! {
                biased;
                () = cancel.cancelled() => Err(SubmissionFailure::Cancelled),
                outcome = tokio::time::timeout(JOB_TIMEOUT, run) => outcome.unwrap_or(Err(SubmissionFailure::TimedOut)),
            };
            result_tx.send_replace(Status::Complete(outcome, Instant::now()));
        });
        state.jobs.insert(
            key,
            Job {
                result: result.clone(),
                location,
                task,
            },
        );
        result
    }

    async fn submit(&self, requests: Vec<Submission>) -> Result<(), PoiError> {
        let results = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.cancel.is_cancelled() {
                return Err(PoiError::SubmissionCancelled);
            }
            state.prune();
            requests
                .into_iter()
                .map(|request| self.enqueue(&mut state, request))
                .collect::<Vec<_>>()
        };
        for mut result in results {
            loop {
                if let Status::Complete(outcome, _) = result.borrow_and_update().clone() {
                    outcome.map_err(SubmissionFailure::into_error)?;
                    break;
                }
                result
                    .changed()
                    .await
                    .map_err(|_| PoiError::SubmissionCancelled)?;
            }
        }
        Ok(())
    }

    pub(crate) async fn submit_single(
        &self,
        context: &SingleCommitmentProofContext,
        tree: u64,
        position: u64,
    ) -> Result<(), PoiError> {
        self.submit(single_submissions(context, tree, position).collect())
            .await
    }

    pub(crate) async fn submit_transact(
        &self,
        version: &str,
        list: FixedBytes<32>,
        index: u64,
        proof: &PreTxPoi,
    ) -> Result<(), PoiError> {
        self.submit(vec![Submission::Transact {
            version: version.to_owned(),
            list,
            index,
            proof: Box::new(proof.clone()),
        }])
        .await
    }

    pub(crate) fn retry_completed(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .jobs
            .retain(|_, job| matches!(*job.result.borrow(), Status::Pending));
    }

    pub(crate) fn cancel(&self) {
        self.cancel.cancel();
    }

    pub(crate) async fn reset(&self) {
        let jobs = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.prepared.clear();
            let jobs = std::mem::take(&mut state.jobs);
            for job in jobs.values() {
                job.task.abort();
            }
            jobs
        };
        for (_, mut job) in jobs {
            let _ = (&mut job.task).await;
        }
    }
}

fn single_submissions(
    context: &SingleCommitmentProofContext,
    tree: u64,
    position: u64,
) -> impl Iterator<Item = Submission> + '_ {
    context
        .pre_transaction_pois_per_txid_leaf_per_list
        .iter()
        .map(move |(list, proofs)| {
            let mut context = context.clone();
            context.pre_transaction_pois_per_txid_leaf_per_list =
                BTreeMap::from([(*list, proofs.clone())]);
            Submission::Single {
                context,
                tree,
                position,
            }
        })
}

#[cfg(test)]
mod tests;
