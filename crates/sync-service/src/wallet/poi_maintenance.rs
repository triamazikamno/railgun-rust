//! Actor-owned POI maintenance scheduling: one in-flight job plus durable rerun intent.

use super::actor::{PoiRemoteJobKey, PoiRemoteJobKind, WalletActorCredential};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum PoiMaintenancePhase {
    #[default]
    Idle,
    Running {
        key: PoiRemoteJobKey,
        started_with_force: bool,
    },
}

/// Spec for spawning a credentialed maintenance job (remote I/O off the actor loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PoiMaintenanceJobSpec {
    pub credential: WalletActorCredential,
    pub key: PoiRemoteJobKey,
    pub force_output_poi_recovery: bool,
}

/// Actor-private controller: at most one maintenance job; force is durable.
#[derive(Debug, Default)]
pub(super) struct PoiMaintenanceController {
    phase: PoiMaintenancePhase,
    force_pending: bool,
    rerun_pending: bool,
}

impl PoiMaintenanceController {
    #[must_use]
    pub(super) fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub(super) fn is_running(&self) -> bool {
        matches!(self.phase, PoiMaintenancePhase::Running { .. })
    }

    #[must_use]
    pub(super) fn force_pending(&self) -> bool {
        self.force_pending
    }

    #[must_use]
    pub(super) fn phase(&self) -> PoiMaintenancePhase {
        self.phase
    }

    /// Record a maintenance request. Requests while busy/unavailable latch one rerun;
    /// force remains sticky until a job starts with force enabled.
    ///
    /// When Idle and `can_start`, returns a job spec. The job absorbs current
    /// `force_pending` (cleared when starting).
    pub(super) fn request(
        &mut self,
        force: bool,
        can_start: bool,
        credential: Option<WalletActorCredential>,
    ) -> Option<PoiMaintenanceJobSpec> {
        if force {
            self.force_pending = true;
        }
        if !can_start || self.is_running() {
            self.rerun_pending = true;
            return None;
        }
        self.try_start(can_start, credential)
    }

    /// Start a job if Idle and allowed. Honors latched force without a new force request.
    pub(super) fn try_start(
        &mut self,
        can_start: bool,
        credential: Option<WalletActorCredential>,
    ) -> Option<PoiMaintenanceJobSpec> {
        if !can_start || self.is_running() {
            return None;
        }
        let credential = credential?;
        let key = PoiRemoteJobKey {
            actor_id: credential.actor_id,
            reset_generation: credential.reset_generation,
            kind: PoiRemoteJobKind::Maintenance,
        };
        let force = self.force_pending;
        self.force_pending = false;
        self.rerun_pending = false;
        self.phase = PoiMaintenancePhase::Running {
            key,
            started_with_force: force,
        };
        Some(PoiMaintenanceJobSpec {
            credential,
            key,
            force_output_poi_recovery: force,
        })
    }

    /// Mark a matching job complete. Returns true when any latched follow-up should start.
    ///
    /// Stale/mismatched keys leave phase unchanged and do not clear `force_pending`.
    pub(super) fn on_job_done(&mut self, key: PoiRemoteJobKey) -> bool {
        match self.phase {
            PoiMaintenancePhase::Running {
                key: running_key, ..
            } if running_key == key => {
                self.phase = PoiMaintenancePhase::Idle;
                self.force_pending || self.rerun_pending
            }
            _ => false,
        }
    }

    /// Drop durable force across AcceptReset / generation advance.
    ///
    /// Does not clear `Running`: the in-flight job still owns the phase until
    /// `on_job_done` so a second concurrent job cannot start.
    pub(super) fn clear_force_on_reset(&mut self) {
        self.force_pending = false;
        self.rerun_pending = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(actor_id: u64, reset_generation: u64) -> WalletActorCredential {
        WalletActorCredential {
            actor_id,
            reset_generation,
        }
    }

    #[test]
    fn idle_force_starts_with_force_and_clears_latch() {
        let mut c = PoiMaintenanceController::new();
        let spec = c.request(true, true, Some(cred(1, 0))).expect("start");
        assert!(spec.force_output_poi_recovery);
        assert!(c.is_running());
        assert!(!c.force_pending());
        assert_eq!(spec.key.actor_id, 1);
        assert_eq!(spec.key.reset_generation, 0);
        assert_eq!(spec.key.kind, PoiRemoteJobKind::Maintenance);
    }

    #[test]
    fn ordinary_while_running_latches_follow_up() {
        let mut c = PoiMaintenanceController::new();
        let first = c.request(false, true, Some(cred(1, 0))).expect("start");
        assert!(!first.force_output_poi_recovery);
        assert!(c.request(false, true, Some(cred(1, 0))).is_none());
        assert!(!c.force_pending());
        assert!(c.is_running());
        assert!(c.on_job_done(first.key));
        assert!(
            c.try_start(true, Some(cred(1, 0)))
                .is_some_and(|spec| !spec.force_output_poi_recovery)
        );
    }

    #[test]
    fn force_while_running_is_sticky_then_follow_up() {
        let mut c = PoiMaintenanceController::new();
        let first = c.request(false, true, Some(cred(1, 0))).expect("start");
        assert!(!first.force_output_poi_recovery);

        assert!(c.request(true, true, Some(cred(1, 0))).is_none());
        assert!(c.force_pending());

        assert!(c.on_job_done(first.key));
        assert!(!c.is_running());
        assert!(c.force_pending());

        let follow = c
            .try_start(true, Some(cred(1, 0)))
            .expect("force follow-up");
        assert!(follow.force_output_poi_recovery);
        assert!(!c.force_pending());
        assert!(c.is_running());
    }

    #[test]
    fn ordinary_start_honors_existing_force_latch() {
        let mut c = PoiMaintenanceController::new();
        let first = c.request(false, true, Some(cred(1, 0))).expect("start");
        let _ = c.request(true, true, Some(cred(1, 0)));
        assert!(c.on_job_done(first.key));

        // Ordinary request after done still absorbs force_pending.
        let follow = c.request(false, true, Some(cred(1, 0))).expect("start");
        assert!(follow.force_output_poi_recovery);
    }

    #[test]
    fn force_while_unavailable_is_latched_until_start() {
        let mut c = PoiMaintenanceController::new();
        assert!(c.request(true, false, None).is_none());
        assert!(c.force_pending());

        let started = c
            .request(false, true, Some(cred(1, 0)))
            .expect("latched force starts when available");
        assert!(started.force_output_poi_recovery);
        assert!(!c.force_pending());
    }

    #[test]
    fn clear_force_on_reset_drops_latch_keeps_running() {
        let mut c = PoiMaintenanceController::new();
        let first = c.request(false, true, Some(cred(1, 0))).expect("start");
        let _ = c.request(true, true, Some(cred(1, 0)));
        assert!(c.force_pending());

        c.clear_force_on_reset();
        assert!(!c.force_pending());
        assert!(c.is_running());

        assert!(!c.on_job_done(first.key));
        assert!(!c.is_running());
        // Ordinary start still allowed after reset; only force latch was cleared.
        let next = c.try_start(true, Some(cred(1, 1))).expect("ordinary start");
        assert!(!next.force_output_poi_recovery);
    }

    #[test]
    fn force_after_reset_while_old_job_running_survives_done() {
        let mut c = PoiMaintenanceController::new();
        let old = c.request(false, true, Some(cred(1, 0))).expect("start");
        c.clear_force_on_reset();
        // New-gen force while old job still in phase.
        assert!(c.request(true, true, Some(cred(1, 1))).is_none());
        assert!(c.force_pending());

        assert!(c.on_job_done(old.key));
        let next = c.try_start(true, Some(cred(1, 1))).expect("new gen force");
        assert!(next.force_output_poi_recovery);
        assert_eq!(next.key.reset_generation, 1);
    }

    #[test]
    fn stale_done_does_not_clear_running_or_force() {
        let mut c = PoiMaintenanceController::new();
        let first = c.request(false, true, Some(cred(1, 0))).expect("start");
        let _ = c.request(true, true, Some(cred(1, 0)));
        let stale = PoiRemoteJobKey {
            actor_id: 1,
            reset_generation: 99,
            kind: PoiRemoteJobKind::Maintenance,
        };
        assert!(!c.on_job_done(stale));
        assert!(c.is_running());
        assert!(c.force_pending());
        assert!(c.on_job_done(first.key));
    }

    #[test]
    fn cannot_start_when_disallowed() {
        let mut c = PoiMaintenanceController::new();
        assert!(c.request(true, false, Some(cred(1, 0))).is_none());
        assert!(c.force_pending());
        assert!(!c.is_running());
    }
}
