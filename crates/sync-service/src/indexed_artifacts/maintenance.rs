//! One background worker for indexed artifact maintenance jobs, with keyed, bounded admission.

#[allow(clippy::wildcard_imports)]
use super::*;

const INDEXED_ARTIFACT_MAINTENANCE_CAPACITY: usize = 8;
const INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES: u64 =
    INDEXED_ARTIFACT_MAX_DECODED_ENVELOPE_BYTES;
type IndexedArtifactMaintenanceJob = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type IndexedArtifactMaintenanceWorker = Shared<IndexedArtifactMaintenanceJob>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IndexedArtifactMaintenanceKey {
    WalletChunk {
        epoch: u64,
        descriptor: Box<IndexedArtifactDescriptor>,
    },
    TxidChunk {
        scope: ChainScope,
        txid_version: String,
        generation: u64,
        cid: String,
        sha256: alloy::primitives::FixedBytes<32>,
    },
    #[cfg(test)]
    Test(u64),
}

impl IndexedArtifactMaintenanceKey {
    #[must_use]
    pub(crate) fn wallet_chunk(descriptor: &IndexedArtifactDescriptor, epoch: u64) -> Self {
        Self::WalletChunk {
            epoch,
            descriptor: Box::new(descriptor.clone()),
        }
    }

    #[must_use]
    pub(crate) fn txid_chunk(
        descriptor: &IndexedArtifactDescriptor,
        txid_version: &str,
        generation: u64,
    ) -> Self {
        Self::TxidChunk {
            scope: descriptor.scope.clone(),
            txid_version: txid_version.to_string(),
            generation,
            cid: descriptor.cid.clone(),
            sha256: descriptor.sha256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexedArtifactMaintenanceAdmission {
    Admitted,
    Duplicate,
    Full,
    PayloadFull,
    Shutdown,
}

#[derive(Clone)]
pub(crate) struct IndexedArtifactMaintenanceScheduler {
    inner: std::sync::Arc<IndexedArtifactMaintenanceSchedulerInner>,
}

struct IndexedArtifactMaintenanceSchedulerInner {
    sender: mpsc::Sender<IndexedArtifactMaintenanceJob>,
    worker: std::sync::Mutex<IndexedArtifactMaintenanceWorkerState>,
    admission: std::sync::Mutex<IndexedArtifactMaintenanceAdmissionState>,
    cancel: CancellationToken,
}

struct IndexedArtifactMaintenanceWorkerState {
    receiver: Option<mpsc::Receiver<IndexedArtifactMaintenanceJob>>,
    worker: Option<IndexedArtifactMaintenanceWorker>,
}

struct IndexedArtifactMaintenanceAdmissionState {
    retained_payload_bytes: u64,
    max_retained_payload_bytes: u64,
    keys: Vec<IndexedArtifactMaintenanceKey>,
}

struct IndexedArtifactMaintenanceReservation {
    inner: std::sync::Weak<IndexedArtifactMaintenanceSchedulerInner>,
    key: Option<IndexedArtifactMaintenanceKey>,
    retained_payload_bytes: u64,
}

impl Drop for IndexedArtifactMaintenanceReservation {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut admission = inner
            .admission
            .lock()
            .expect("indexed artifact maintenance admission lock poisoned");
        admission.retained_payload_bytes = admission
            .retained_payload_bytes
            .saturating_sub(self.retained_payload_bytes);
        if let Some(key) = self.key.take()
            && let Some(index) = admission.keys.iter().position(|reserved| *reserved == key)
        {
            admission.keys.swap_remove(index);
        }
    }
}

impl Drop for IndexedArtifactMaintenanceSchedulerInner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl IndexedArtifactMaintenanceScheduler {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::with_limits(
            INDEXED_ARTIFACT_MAINTENANCE_CAPACITY,
            INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES,
        )
    }

    fn with_limits(capacity: usize, max_retained_payload_bytes: u64) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self {
            inner: std::sync::Arc::new(IndexedArtifactMaintenanceSchedulerInner {
                sender,
                worker: std::sync::Mutex::new(IndexedArtifactMaintenanceWorkerState {
                    receiver: Some(receiver),
                    worker: None,
                }),
                admission: std::sync::Mutex::new(IndexedArtifactMaintenanceAdmissionState {
                    retained_payload_bytes: 0,
                    max_retained_payload_bytes,
                    keys: Vec::new(),
                }),
                cancel: CancellationToken::new(),
            }),
        }
    }

    pub(crate) fn try_schedule<F>(
        &self,
        key: IndexedArtifactMaintenanceKey,
        retained_payload_bytes: u64,
        job: F,
    ) -> IndexedArtifactMaintenanceAdmission
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.inner.cancel.is_cancelled() {
            return IndexedArtifactMaintenanceAdmission::Shutdown;
        }

        let reservation = {
            let mut admission = self
                .inner
                .admission
                .lock()
                .expect("indexed artifact maintenance admission lock poisoned");
            if admission.keys.contains(&key) {
                return IndexedArtifactMaintenanceAdmission::Duplicate;
            }
            if retained_payload_bytes
                > admission
                    .max_retained_payload_bytes
                    .saturating_sub(admission.retained_payload_bytes)
            {
                return IndexedArtifactMaintenanceAdmission::PayloadFull;
            }
            admission.retained_payload_bytes = admission
                .retained_payload_bytes
                .saturating_add(retained_payload_bytes);
            admission.keys.push(key.clone());
            IndexedArtifactMaintenanceReservation {
                inner: std::sync::Arc::downgrade(&self.inner),
                key: Some(key),
                retained_payload_bytes,
            }
        };

        let mut worker = self
            .inner
            .worker
            .lock()
            .expect("indexed artifact maintenance worker lock poisoned");
        if self.inner.cancel.is_cancelled() {
            return IndexedArtifactMaintenanceAdmission::Shutdown;
        }
        Self::ensure_worker(&mut worker, &self.inner.cancel);
        let reserved_job = async move {
            let _reservation = reservation;
            job.await;
        };
        match self.inner.sender.try_send(Box::pin(reserved_job)) {
            Ok(()) => IndexedArtifactMaintenanceAdmission::Admitted,
            Err(mpsc::error::TrySendError::Full(_)) => IndexedArtifactMaintenanceAdmission::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => {
                IndexedArtifactMaintenanceAdmission::Shutdown
            }
        }
    }

    pub(crate) async fn shutdown(&self) {
        let worker = {
            let worker = self
                .inner
                .worker
                .lock()
                .expect("indexed artifact maintenance worker lock poisoned");
            self.inner.cancel.cancel();
            worker.worker.clone()
        };
        if let Some(worker) = worker {
            worker.await;
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.inner.cancel.cancel();
    }

    fn ensure_worker(
        state: &mut IndexedArtifactMaintenanceWorkerState,
        cancel: &CancellationToken,
    ) {
        let Some(mut receiver) = state.receiver.take() else {
            return;
        };
        let worker_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            loop {
                let job = tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => break,
                    job = receiver.recv() => job,
                };
                let Some(job) = job else {
                    break;
                };
                tokio::select! {
                    biased;
                    () = worker_cancel.cancelled() => break,
                    () = job => {}
                }
            }
        });
        state.worker = Some(
            async move {
                let _ = handle.await;
            }
            .boxed()
            .shared(),
        );
    }
}

#[cfg(test)]
impl IndexedArtifactMaintenanceScheduler {
    fn with_capacity(capacity: usize) -> Self {
        Self::with_limits(
            capacity,
            INDEXED_ARTIFACT_MAINTENANCE_MAX_RETAINED_PAYLOAD_BYTES,
        )
    }
}

#[cfg(test)]
mod tests;
