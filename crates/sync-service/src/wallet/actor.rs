//! Wallet actor ownership core.
//!
//! Invariants:
//! 1. Only the wallet actor mutates private durable state and publishes mirrors.
//! 2. Actor turns do local work / spawn remote jobs; they do not await remote POI/RPC.
//! 3. Remote POI jobs re-enter via [`crate::wallet::WalletPrivateApplyClient`] (or
//!    [`WalletRemoteDone`]) for durable apply; jobs never write UTXO mirrors directly.
//! 4. Remote results apply only if actor credential is still current.
//! 5. While durable pending reset is set, published private view is fenced; chain
//!    scheduling uses public `schedulable_progress` / `wait_schedulable_progress` only
//!    (cursor + generation from one view snapshot; never authority generation).
//!
//! Lifecycle is separate from [`CancellationToken`]: cancel stops async work and may
//! drive Prepared/Active → Stopping; publication authority is lifecycle-based.
//!
//! The lifecycle fence is a short `std::sync::Mutex` used only for lifecycle transitions
//! and Active/Stopping private applies. It must never be held across remote I/O.

use std::marker::PhantomData;
use std::sync::Mutex;

/// Publication and apply authority for a wallet actor instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub(crate) enum WalletActorLifecycle {
    /// Bootstrap may apply durable state, but the actor is not registered or mailbox-active yet.
    Prepared = 0,
    /// Normal apply and publish.
    Active = 1,
    /// Cancel observed while still current; exactly one terminal Shutdown publish; no durable commits.
    Stopping = 2,
    /// Unregistered or replaced; publish only the terminal Retired view, apply nothing.
    Retired = 3,
}

impl WalletActorLifecycle {
    /// Durable private commits and non-terminal publications.
    pub(crate) const fn allows_durable_commits(self) -> bool {
        matches!(self, Self::Prepared | Self::Active)
    }

    /// Terminal Shutdown readiness only.
    pub(crate) const fn allows_terminal_shutdown_publish(self) -> bool {
        matches!(self, Self::Stopping)
    }
}

#[derive(Debug)]
struct LifecycleInner {
    state: WalletActorLifecycle,
    terminal_shutdown_published: bool,
}

/// Shared lifecycle cell for all [`crate::wallet::WalletHandle`] clones of one actor.
#[derive(Debug)]
pub(crate) struct WalletActorLifecycleCell {
    fence: Mutex<LifecycleInner>,
}

impl Default for WalletActorLifecycleCell {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletActorLifecycleCell {
    pub(crate) const fn new() -> Self {
        Self::with_state(WalletActorLifecycle::Active)
    }

    pub(crate) const fn new_prepared() -> Self {
        Self::with_state(WalletActorLifecycle::Prepared)
    }

    const fn with_state(state: WalletActorLifecycle) -> Self {
        Self {
            fence: Mutex::new(LifecycleInner {
                state,
                terminal_shutdown_published: false,
            }),
        }
    }

    fn with_fence<R>(&self, f: impl FnOnce(&mut LifecycleInner) -> R) -> R {
        let mut guard = self
            .fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    pub(crate) fn get(&self) -> WalletActorLifecycle {
        self.with_fence(|inner| inner.state)
    }

    /// Prepared/Active → Stopping. Returns true if this call performed the transition.
    #[cfg(test)]
    pub(crate) fn mark_stopping(&self) -> bool {
        self.mark_stopping_with(|| {})
    }

    /// Prepared/Active → Stopping, publishing terminal session state under the fence.
    pub(crate) fn mark_stopping_with(&self, publish: impl FnOnce()) -> bool {
        self.with_fence(|inner| {
            if matches!(
                inner.state,
                WalletActorLifecycle::Prepared | WalletActorLifecycle::Active
            ) {
                inner.state = WalletActorLifecycle::Stopping;
                publish();
                true
            } else {
                false
            }
        })
    }

    /// Prepared → Active. Registration must be installed before this transition.
    pub(crate) fn activate(&self) -> bool {
        self.with_fence(|inner| {
            if inner.state == WalletActorLifecycle::Prepared {
                inner.state = WalletActorLifecycle::Active;
                true
            } else {
                false
            }
        })
    }

    /// Any → Retired under the lifecycle fence. Invokes `flip_identity` before unlock
    /// so identity and lifecycle flip atomically w.r.t. terminal publish.
    pub(crate) fn mark_retired(&self, flip_identity: impl FnOnce()) {
        self.with_fence(|inner| {
            inner.state = WalletActorLifecycle::Retired;
            // Poison terminal take so a concurrent shutdown path cannot publish after retire.
            inner.terminal_shutdown_published = true;
            flip_identity();
        });
    }

    /// If Stopping, not yet published, and `is_current` is true, marks published and runs
    /// `publish` while still holding the lifecycle fence.
    pub(crate) fn publish_terminal_shutdown_if_allowed(
        &self,
        is_current: bool,
        publish: impl FnOnce(),
    ) -> bool {
        self.with_fence(|inner| {
            if !inner.state.allows_terminal_shutdown_publish()
                || inner.terminal_shutdown_published
                || !is_current
            {
                return false;
            }
            inner.terminal_shutdown_published = true;
            publish();
            true
        })
    }

    /// Runs `apply` only while lifecycle allows private commits and `is_current` is true,
    /// holding the lifecycle fence for the entire synchronous apply (never across remote I/O).
    ///
    /// The apply token is lifetime-bound via HRTB so it cannot escape the closure.
    pub(crate) fn with_active_apply<R>(
        &self,
        is_current: bool,
        apply: impl for<'a> FnOnce(WalletActorApplyToken<'a>) -> R,
    ) -> Result<R, ()> {
        self.with_fence(|inner| {
            if !inner.state.allows_durable_commits() || !is_current {
                return Err(());
            }
            Ok(apply(WalletActorApplyToken {
                _fence: PhantomData,
            }))
        })
    }

    /// Runs request admission only while the mailbox actor is Active and current.
    pub(crate) fn with_active_request<R>(
        &self,
        is_current: bool,
        request: impl FnOnce() -> R,
    ) -> Result<R, ()> {
        self.with_fence(|inner| {
            if inner.state != WalletActorLifecycle::Active || !is_current {
                return Err(());
            }
            Ok(request())
        })
    }
}

/// Proof that a private apply is running under the lifecycle fence while apply-authorized.
/// Lifetime is bound to the fence hold; cannot escape [`WalletActorLifecycleCell::with_active_apply`].
#[derive(Debug)]
pub(crate) struct WalletActorApplyToken<'a> {
    _fence: PhantomData<&'a LifecycleInner>,
}

/// Alias used by durable commit constructors (same capability as apply token).
pub(crate) type WalletActorCommitToken<'a> = WalletActorApplyToken<'a>;

/// Credential for remote POI jobs re-entering the actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WalletActorCredential {
    pub actor_id: u64,
    pub reset_generation: u64,
}

impl WalletActorCredential {
    #[must_use]
    pub(crate) fn current_for(handle: &crate::wallet::WalletHandle) -> Self {
        Self {
            actor_id: handle.actor_id(),
            reset_generation: handle.authority_reset_generation(),
        }
    }

    #[must_use]
    pub(crate) fn is_current(self, handle: &crate::wallet::WalletHandle) -> bool {
        handle.is_current_actor()
            && handle.actor_id() == self.actor_id
            && handle.authority_reset_generation() == self.reset_generation
            && handle.lifecycle().allows_durable_commits()
    }
}

/// Precise in-flight key for remote POI maintenance (one concurrent maintenance job per generation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PoiRemoteJobKey {
    pub actor_id: u64,
    pub reset_generation: u64,
    pub kind: PoiRemoteJobKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PoiRemoteJobKind {
    /// Verify submitted + optional force-resubmit + recovery + submit observations.
    Maintenance,
}

/// Remote work completion messages re-entering the wallet actor (never applied off-loop bookkeeping only).
#[derive(Debug)]
pub(crate) enum WalletRemoteDone {
    PoiMaintenance {
        credential: WalletActorCredential,
        key: PoiRemoteJobKey,
        recovered: usize,
        forced_pending_attempts: usize,
        submitted: usize,
        verified_completed: usize,
        verified_pending: usize,
        verified_errors: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    };
    use std::time::Duration;

    #[test]
    fn retire_poisons_terminal_shutdown_publish() {
        let cell = WalletActorLifecycleCell::new();
        assert!(cell.mark_stopping());
        cell.mark_retired(|| {});
        assert_eq!(cell.get(), WalletActorLifecycle::Retired);
        assert!(!cell.publish_terminal_shutdown_if_allowed(true, || {
            panic!("retired actor must not publish terminal shutdown");
        }));
    }

    #[test]
    fn terminal_shutdown_publish_runs_under_fence_once() {
        let cell = WalletActorLifecycleCell::new();
        assert!(cell.mark_stopping());
        let mut published = 0_u32;
        assert!(cell.publish_terminal_shutdown_if_allowed(true, || {
            published += 1;
        }));
        assert_eq!(published, 1);
        assert!(!cell.publish_terminal_shutdown_if_allowed(true, || {
            published += 1;
        }));
        assert_eq!(published, 1);
    }

    #[test]
    fn retire_flips_identity_under_same_fence_as_state() {
        let cell = WalletActorLifecycleCell::new();
        let actor_id = AtomicU64::new(7);
        cell.mark_retired(|| {
            actor_id.store(0, Ordering::Release);
        });
        assert_eq!(cell.get(), WalletActorLifecycle::Retired);
        assert_eq!(actor_id.load(Ordering::Acquire), 0);
    }

    #[test]
    fn active_apply_rejects_after_retire() {
        let cell = WalletActorLifecycleCell::new();
        assert!(
            cell.with_active_apply(true, |_token| 1_u32)
                .is_ok_and(|v| v == 1)
        );
        cell.mark_retired(|| {});
        assert!(cell.with_active_apply(true, |_token| 2_u32).is_err());
    }

    #[test]
    fn retire_waits_for_in_flight_durable_apply_and_fences_later_applies() {
        let cell = Arc::new(WalletActorLifecycleCell::new());
        let (apply_started_tx, apply_started_rx) = mpsc::channel();
        let (release_apply_tx, release_apply_rx) = mpsc::channel();
        let apply_cell = Arc::clone(&cell);
        let apply = std::thread::spawn(move || {
            apply_cell
                .with_active_apply(true, |_token| {
                    apply_started_tx.send(()).expect("signal active apply");
                    release_apply_rx.recv().expect("release active apply");
                })
                .expect("active apply accepted");
        });
        apply_started_rx.recv().expect("active apply started");

        let (retire_started_tx, retire_started_rx) = mpsc::channel();
        let (retired_tx, retired_rx) = mpsc::channel();
        let retire_cell = Arc::clone(&cell);
        let retire = std::thread::spawn(move || {
            retire_started_tx.send(()).expect("signal retire attempt");
            retire_cell.mark_retired(|| {});
            retired_tx.send(()).expect("signal retirement");
        });
        retire_started_rx.recv().expect("retire attempt started");
        assert!(retired_rx.recv_timeout(Duration::from_millis(25)).is_err());

        release_apply_tx.send(()).expect("release durable apply");
        apply.join().expect("join active apply");
        retired_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("retirement completed");
        retire.join().expect("join retirement");
        assert_eq!(cell.get(), WalletActorLifecycle::Retired);
        assert!(cell.with_active_apply(true, |_token| ()).is_err());
    }

    #[test]
    fn active_apply_rejects_when_not_current() {
        let cell = WalletActorLifecycleCell::new();
        assert!(cell.with_active_apply(false, |_token| ()).is_err());
    }

    // Compile-fail intent: token must not escape. If this compiled, HRTB is broken.
    // fn token_cannot_escape() {
    //     let cell = WalletActorLifecycleCell::new();
    //     let _escaped = cell.with_active_apply(true, |token| token).unwrap();
    // }
}
