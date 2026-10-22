//! Per-transaction routes and admission spacing for PPOI submissions.
//!
//! A submission tells the POI node that its sender made one Railgun
//! transaction. When the chain config sets a route provider, each
//! transaction's submissions leave over a route opened for that transaction
//! alone. One scheduler per `SyncManager` admits new transactions one at a
//! time, a random gap apart, and bounds how many routes are open. Callers it
//! cannot admit yet are deferred, never blocked.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use alloy::primitives::U256;
use async_trait::async_trait;
use poi::SensitiveUrl;
use poi::poi::PoiRpcClient;
use rand::RngExt;
use rand::rngs::StdRng;
use tokio::sync::{OnceCell, watch};
use tokio::time::Instant;

use crate::wallet::PendingOutputPoiSubmitter;

pub(crate) const MIN_ADMISSION_GAP: Duration = Duration::from_secs(20);
pub(crate) const MAX_ADMISSION_GAP: Duration = Duration::from_mins(2);
pub(crate) const MAX_OPEN_ROUTES: usize = 2;

/// Opens routes that carry one Railgun transaction's PPOI submissions.
#[async_trait]
pub trait PoiSubmissionRouteProvider: Send + Sync {
    /// Opens a fresh route that shares no circuit or connection with other
    /// traffic.
    async fn isolated_route(&self) -> Result<PoiSubmissionRoute, PoiSubmissionRouteError>;
}

/// An isolated route's client and whatever keeps that client usable.
pub struct PoiSubmissionRoute {
    client: reqwest::Client,
    guard: Box<dyn Any + Send + Sync>,
}

impl PoiSubmissionRoute {
    /// The client is used only while `guard` lives and is dropped before it.
    #[must_use]
    pub fn new(client: reqwest::Client, guard: impl Any + Send + Sync) -> Self {
        Self {
            client,
            guard: Box::new(guard),
        }
    }
}

/// Why an isolated route could not be opened. The message must not contain
/// endpoint URLs or credentials.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct PoiSubmissionRouteError {
    message: String,
}

impl PoiSubmissionRouteError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PoiSubmissionSchedulerConfig {
    pub(crate) min_admission_gap: Duration,
    pub(crate) max_admission_gap: Duration,
    pub(crate) max_open_routes: usize,
}

impl Default for PoiSubmissionSchedulerConfig {
    fn default() -> Self {
        Self {
            min_admission_gap: MIN_ADMISSION_GAP,
            max_admission_gap: MAX_ADMISSION_GAP,
            max_open_routes: MAX_OPEN_ROUTES,
        }
    }
}

/// Chain id and Railgun TXID of one transaction's submissions.
type SubmissionKey = (u64, U256);

/// Admission state shared by every chain and wallet of one `SyncManager`.
pub(crate) struct PoiSubmissionScheduler {
    config: PoiSubmissionSchedulerConfig,
    state: StdMutex<SchedulerState>,
    changed: watch::Sender<()>,
}

struct SchedulerState {
    /// Earliest admission of a new transaction; `None` while idle.
    next_admission: Option<Instant>,
    open_routes: usize,
    active: HashMap<SubmissionKey, Weak<KeySlot>>,
    rng: StdRng,
}

/// Result of [`PoiSubmissionScheduler::try_reserve`].
pub(crate) enum PoiSubmissionAdmission {
    /// The transaction's active reservation, or a new one.
    Admitted(PoiSubmissionReservation),
    /// Not admitted now. `until` is when spacing ends; `None` means the route
    /// limit is full and [`PoiSubmissionScheduler::changed`] marks a release.
    Deferred { until: Option<Instant> },
}

impl PoiSubmissionScheduler {
    pub(crate) fn new(config: PoiSubmissionSchedulerConfig, rng: StdRng) -> Arc<Self> {
        Arc::new(Self {
            config,
            state: StdMutex::new(SchedulerState {
                next_admission: None,
                open_routes: 0,
                active: HashMap::new(),
                rng,
            }),
            changed: watch::channel(()).0,
        })
    }

    fn lock(&self) -> MutexGuard<'_, SchedulerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The transaction's active reservation, if it has one. Never admits.
    pub(crate) fn join(
        &self,
        chain_id: u64,
        railgun_txid: U256,
    ) -> Option<PoiSubmissionReservation> {
        self.lock()
            .active
            .get(&(chain_id, railgun_txid))
            .and_then(Weak::upgrade)
            .map(|slot| PoiSubmissionReservation { slot })
    }

    /// Joins the transaction's active reservation without spacing, or admits
    /// it when spacing has elapsed and a route slot is free. Never waits.
    pub(crate) fn try_reserve(
        self: &Arc<Self>,
        chain_id: u64,
        railgun_txid: U256,
    ) -> PoiSubmissionAdmission {
        let key = (chain_id, railgun_txid);
        let mut state = self.lock();
        if let Some(slot) = state.active.get(&key).and_then(Weak::upgrade) {
            return PoiSubmissionAdmission::Admitted(PoiSubmissionReservation { slot });
        }
        let now = Instant::now();
        if let Some(next) = state.next_admission.filter(|next| now < *next) {
            return PoiSubmissionAdmission::Deferred { until: Some(next) };
        }
        if state.open_routes >= self.config.max_open_routes {
            return PoiSubmissionAdmission::Deferred { until: None };
        }
        let gap = state
            .rng
            .random_range(self.config.min_admission_gap..=self.config.max_admission_gap);
        state.next_admission = Some(now + gap);
        state.open_routes += 1;
        let slot = Arc::new(KeySlot {
            scheduler: Arc::clone(self),
            key,
            released: AtomicBool::new(false),
            route: OnceCell::new(),
        });
        state.active.insert(key, Arc::downgrade(&slot));
        PoiSubmissionAdmission::Admitted(PoiSubmissionReservation { slot })
    }

    /// Uniform index below `len`, which must be positive, from the
    /// scheduler's generator.
    pub(crate) fn choose_index(&self, len: usize) -> usize {
        self.lock().rng.random_range(0..len)
    }

    /// A receiver marked changed whenever a route slot frees.
    pub(crate) fn changed(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    fn release(&self, slot: &KeySlot) {
        {
            let mut state = self.lock();
            state.open_routes -= 1;
            if state
                .active
                .get(&slot.key)
                .is_some_and(|active| std::ptr::eq(active.as_ptr(), slot))
            {
                state.active.remove(&slot.key);
            }
        }
        self.changed.send_replace(());
    }
}

/// One admitted transaction's route slot. It frees when its open fails or
/// when the last reservation or permit for it drops.
struct KeySlot {
    scheduler: Arc<PoiSubmissionScheduler>,
    key: SubmissionKey,
    released: AtomicBool,
    route: OnceCell<Result<Arc<OpenRoute>, PoiSubmissionRouteError>>,
}

impl KeySlot {
    fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.scheduler.release(self);
        }
    }
}

impl Drop for KeySlot {
    fn drop(&mut self) {
        self.release();
    }
}

/// Fields drop in order, so the submitter's client goes before the guard.
struct OpenRoute {
    submitter: Arc<dyn PendingOutputPoiSubmitter>,
    _guard: Box<dyn Any + Send + Sync>,
}

/// A transaction's admission, held from reservation until its last queued
/// or running submission ends. Clones share the admission and its route.
#[derive(Clone)]
pub(crate) struct PoiSubmissionReservation {
    slot: Arc<KeySlot>,
}

impl PoiSubmissionReservation {
    /// Opens the transaction's route, or waits for the open already under
    /// way. A failed open frees the slot at once, and every holder gets the
    /// error; callers defer and never fall back to a shared client.
    pub(crate) async fn open(
        &self,
        routing: &PoiSubmissionRouting,
    ) -> Result<PoiSubmissionPermit, PoiSubmissionRouteError> {
        let route = self
            .slot
            .route
            .get_or_init(|| async {
                match routing.provider.isolated_route().await {
                    Ok(PoiSubmissionRoute { client, guard }) => Ok(Arc::new(OpenRoute {
                        submitter: (routing.submitter)(client),
                        _guard: guard,
                    })),
                    Err(err) => {
                        self.slot.release();
                        Err(err)
                    }
                }
            })
            .await;
        route.clone().map(|route| PoiSubmissionPermit {
            route,
            _slot: Arc::clone(&self.slot),
        })
    }
}

/// An open route for one transaction. Clones share the route.
#[derive(Clone)]
pub(crate) struct PoiSubmissionPermit {
    route: Arc<OpenRoute>,
    _slot: Arc<KeySlot>,
}

impl PoiSubmissionPermit {
    /// Submitter over this route. Borrowed so that it cannot outlive the
    /// permit.
    pub(crate) fn submitter(&self) -> &dyn PendingOutputPoiSubmitter {
        self.route.submitter.as_ref()
    }
}

type RouteSubmitterFactory =
    Arc<dyn Fn(reqwest::Client) -> Arc<dyn PendingOutputPoiSubmitter> + Send + Sync>;

/// What a chain's submitters need to send over isolated routes: the shared
/// scheduler, the chain's route provider, and how a route's client becomes a
/// POI submitter.
#[derive(Clone)]
pub(crate) struct PoiSubmissionRouting {
    pub(crate) scheduler: Arc<PoiSubmissionScheduler>,
    provider: Arc<dyn PoiSubmissionRouteProvider>,
    submitter: RouteSubmitterFactory,
}

impl PoiSubmissionRouting {
    pub(crate) fn new(
        scheduler: Arc<PoiSubmissionScheduler>,
        provider: Arc<dyn PoiSubmissionRouteProvider>,
        poi_url: SensitiveUrl,
    ) -> Self {
        Self::with_submitter_factory(
            scheduler,
            provider,
            Arc::new(
                move |client: reqwest::Client| -> Arc<dyn PendingOutputPoiSubmitter> {
                    Arc::new(PoiRpcClient::with_http_client(poi_url.clone(), client))
                },
            ),
        )
    }

    fn with_submitter_factory(
        scheduler: Arc<PoiSubmissionScheduler>,
        provider: Arc<dyn PoiSubmissionRouteProvider>,
        submitter: RouteSubmitterFactory,
    ) -> Self {
        Self {
            scheduler,
            provider,
            submitter,
        }
    }
}

/// Recording routes and seeded schedulers for submission tests.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tokio::sync::watch;

    use super::{
        PoiSubmissionRoute, PoiSubmissionRouteError, PoiSubmissionRouteProvider,
        PoiSubmissionRouting, PoiSubmissionScheduler, PoiSubmissionSchedulerConfig,
    };
    use crate::chain::poi_submitter_test_support::RecordingPoiTransport;
    use crate::wallet::PendingOutputPoiSubmitter;

    pub(crate) fn seeded_scheduler(seed: u64) -> Arc<PoiSubmissionScheduler> {
        PoiSubmissionScheduler::new(
            PoiSubmissionSchedulerConfig::default(),
            StdRng::seed_from_u64(seed),
        )
    }

    /// Provider whose routes each send through their own recording transport.
    pub(crate) struct RecordingRoutes {
        opens: AtomicUsize,
        fail: AtomicBool,
        open_gate: watch::Sender<bool>,
        routes: Mutex<Vec<Arc<RecordingPoiTransport>>>,
    }

    impl RecordingRoutes {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                opens: AtomicUsize::new(0),
                fail: AtomicBool::new(false),
                open_gate: watch::channel(true).0,
                routes: Mutex::default(),
            })
        }

        /// Routing over these routes; the submitter of the `i`th opened route
        /// is `routes()[i]`.
        pub(crate) fn routing(
            self: &Arc<Self>,
            scheduler: Arc<PoiSubmissionScheduler>,
        ) -> PoiSubmissionRouting {
            let recorder = Arc::clone(self);
            PoiSubmissionRouting::with_submitter_factory(
                scheduler,
                Arc::clone(self) as Arc<dyn PoiSubmissionRouteProvider>,
                Arc::new(
                    move |_client: reqwest::Client| -> Arc<dyn PendingOutputPoiSubmitter> {
                        let transport = Arc::new(RecordingPoiTransport::default());
                        recorder
                            .routes
                            .lock()
                            .expect("routes lock")
                            .push(Arc::clone(&transport));
                        transport
                    },
                ),
            )
        }

        /// Provider calls, including failed and pending opens.
        pub(crate) fn opens(&self) -> usize {
            self.opens.load(Ordering::Acquire)
        }

        pub(crate) fn routes(&self) -> Vec<Arc<RecordingPoiTransport>> {
            self.routes.lock().expect("routes lock").clone()
        }

        pub(crate) fn fail_opens(&self, fail: bool) {
            self.fail.store(fail, Ordering::Release);
        }

        /// While the gate is closed, opens wait.
        pub(crate) fn set_open_gate(&self, open: bool) {
            self.open_gate.send_replace(open);
        }
    }

    #[async_trait]
    impl PoiSubmissionRouteProvider for RecordingRoutes {
        async fn isolated_route(&self) -> Result<PoiSubmissionRoute, PoiSubmissionRouteError> {
            self.opens.fetch_add(1, Ordering::AcqRel);
            let mut gate = self.open_gate.subscribe();
            let _ = gate.wait_for(|open| *open).await;
            if self.fail.load(Ordering::Acquire) {
                return Err(PoiSubmissionRouteError::new("route unavailable"));
            }
            Ok(PoiSubmissionRoute::new(reqwest::Client::new(), ()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use alloy::primitives::U256;
    use tokio::time::Instant;

    use super::test_support::{RecordingRoutes, seeded_scheduler};
    use super::{
        MAX_ADMISSION_GAP, MIN_ADMISSION_GAP, PoiSubmissionAdmission, PoiSubmissionReservation,
        PoiSubmissionScheduler,
    };

    const CHAIN_ID: u64 = 1;

    fn reserve(scheduler: &Arc<PoiSubmissionScheduler>, txid: u64) -> PoiSubmissionReservation {
        match scheduler.try_reserve(CHAIN_ID, U256::from(txid)) {
            PoiSubmissionAdmission::Admitted(reservation) => reservation,
            PoiSubmissionAdmission::Deferred { until } => {
                panic!("TXID {txid} deferred until {until:?}")
            }
        }
    }

    fn deferral(scheduler: &Arc<PoiSubmissionScheduler>, txid: u64) -> Option<Instant> {
        match scheduler.try_reserve(CHAIN_ID, U256::from(txid)) {
            PoiSubmissionAdmission::Admitted(_) => panic!("TXID {txid} admitted"),
            PoiSubmissionAdmission::Deferred { until } => until,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn second_txid_waits_for_random_gap() {
        let scheduler = seeded_scheduler(0);
        let start = Instant::now();
        let _first = reserve(&scheduler, 1);

        let until = deferral(&scheduler, 2).expect("spacing deferral");
        assert!((start + MIN_ADMISSION_GAP..=start + MAX_ADMISSION_GAP).contains(&until));
        tokio::time::advance(
            until
                .duration_since(start)
                .saturating_sub(Duration::from_millis(1)),
        )
        .await;
        assert_eq!(deferral(&scheduler, 2), Some(until));

        tokio::time::advance(Duration::from_millis(1)).await;
        let _second = reserve(&scheduler, 2);

        let next = deferral(&scheduler, 3).expect("spacing deferral");
        let gap = next.duration_since(until);
        assert!((MIN_ADMISSION_GAP..=MAX_ADMISSION_GAP).contains(&gap));
        assert_ne!(gap, until.duration_since(start), "each gap is drawn anew");
    }

    #[tokio::test(start_paused = true)]
    async fn route_limit_defers_without_until_and_frees_on_permit_drop() {
        let routes = RecordingRoutes::new();
        let scheduler = seeded_scheduler(0);
        let routing = routes.routing(Arc::clone(&scheduler));
        let changed = scheduler.changed();
        let mut permits = Vec::new();
        for txid in 1..=2 {
            let permit = reserve(&scheduler, txid).open(&routing).await;
            permits.push(permit.expect("route opens"));
            tokio::time::advance(MAX_ADMISSION_GAP).await;
        }

        assert_eq!(deferral(&scheduler, 3), None, "route limit is full");
        assert!(!changed.has_changed().expect("scheduler alive"));
        drop(permits.pop());
        assert!(changed.has_changed().expect("scheduler alive"));

        let third = reserve(&scheduler, 3);
        assert!(
            deferral(&scheduler, 2).is_some(),
            "TXID 2 needs a new spaced admission"
        );
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        assert_eq!(deferral(&scheduler, 4), None, "the limit still holds");

        drop(third);
        reserve(&scheduler, 2)
            .open(&routing)
            .await
            .expect("fresh route opens");
        assert_eq!(routes.routes().len(), 3, "TXID 2 gets a fresh route");
    }

    #[tokio::test(start_paused = true)]
    async fn same_txid_joins_active_route_without_spacing() {
        let routes = RecordingRoutes::new();
        let scheduler = seeded_scheduler(0);
        let routing = routes.routing(Arc::clone(&scheduler));

        let first = reserve(&scheduler, 1)
            .open(&routing)
            .await
            .expect("route opens");
        let joined = reserve(&scheduler, 1).open(&routing).await.expect("joined");

        assert!(Arc::ptr_eq(&first.route, &joined.route));
        assert_eq!(routes.opens(), 1);
        assert!(
            matches!(
                scheduler.try_reserve(CHAIN_ID + 1, U256::from(1)),
                PoiSubmissionAdmission::Deferred { until: Some(_) }
            ),
            "the same TXID on another chain is another transaction"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_open_releases_slot_and_yields_no_client() {
        let routes = RecordingRoutes::new();
        let scheduler = seeded_scheduler(0);
        let routing = routes.routing(Arc::clone(&scheduler));
        routes.fail_opens(true);
        let reservation = reserve(&scheduler, 1);
        let joined = reserve(&scheduler, 1);

        assert!(reservation.open(&routing).await.is_err());
        assert!(joined.open(&routing).await.is_err());
        assert_eq!(routes.opens(), 1, "holders share the failed open");
        assert!(routes.routes().is_empty(), "no submitter was built");
        assert!(deferral(&scheduler, 1).is_some(), "the key is released");

        // Both slots are free while the failed reservation is still held.
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        let _second = reserve(&scheduler, 2);
        tokio::time::advance(MAX_ADMISSION_GAP).await;
        let _third = reserve(&scheduler, 3);
    }
}
