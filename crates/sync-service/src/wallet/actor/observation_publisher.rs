#[allow(clippy::wildcard_imports)]
use super::*;

impl WalletObservationPublisher {
    pub(crate) fn new(
        initial_view: WalletViewState,
    ) -> (Arc<Self>, watch::Receiver<WalletObservation>) {
        let (sender, receiver) = watch::channel(WalletObservation::new(
            initial_view,
            WalletReadiness::Syncing,
        ));
        (Arc::new(Self { sender }), receiver)
    }

    pub(crate) fn publish_readiness(&self, readiness: WalletReadiness) {
        let _ = self.sender.send_if_modified(|published| {
            if published.readiness() == &readiness {
                false
            } else {
                *published = WalletObservation::with_ppoi_workflow_projection(
                    published.view().clone(),
                    readiness,
                    *published.ppoi_workflow_status(),
                    published.ppoi_submission_statuses_arc(),
                );
                true
            }
        });
    }

    pub(crate) fn publish_view(&self, view: WalletViewState) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(&view, WalletViewState::Current(_)) {
                published.ppoi_submission_statuses_arc()
            } else {
                Arc::from([])
            };
            let observation = WalletObservation::with_ppoi_workflow_projection(
                view,
                published.readiness().clone(),
                *published.ppoi_workflow_status(),
                submissions,
            );
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    pub(crate) fn publish(&self, view: WalletViewState, readiness: WalletReadiness) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(&view, WalletViewState::Current(_)) {
                published.ppoi_submission_statuses_arc()
            } else {
                Arc::from([])
            };
            let observation = WalletObservation::with_ppoi_workflow_projection(
                view,
                readiness,
                *published.ppoi_workflow_status(),
                submissions,
            );
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    pub(super) fn publish_with_ppoi_workflow_projection(
        &self,
        view: WalletViewState,
        readiness: WalletReadiness,
        projection: WalletPpoiWorkflowProjection,
    ) {
        let submissions = if matches!(&view, WalletViewState::Current(_)) {
            projection.submissions
        } else {
            Arc::from([])
        };
        let observation = WalletObservation::with_ppoi_workflow_projection(
            view,
            readiness,
            projection.status,
            submissions,
        );
        let _ = self.sender.send_if_modified(|published| {
            if published == &observation {
                false
            } else {
                published.clone_from(&observation);
                true
            }
        });
    }

    pub(crate) fn publish_ppoi_workflow_projection(
        &self,
        status: WalletPpoiWorkflowStatus,
        submissions: Arc<[WalletPpoiSubmissionStatus]>,
    ) {
        let _ = self.sender.send_if_modified(|published| {
            let submissions = if matches!(published.view(), WalletViewState::Current(_)) {
                submissions
            } else {
                Arc::from([])
            };
            if published.ppoi_workflow_status() == &status
                && published.ppoi_submission_statuses() == submissions.as_ref()
            {
                false
            } else {
                *published = WalletObservation::with_ppoi_workflow_projection(
                    published.view().clone(),
                    published.readiness().clone(),
                    status,
                    submissions,
                );
                true
            }
        });
    }

    pub(crate) fn publish_ppoi_workflow_status(&self, status: WalletPpoiWorkflowStatus) {
        let submissions = self.sender.borrow().ppoi_submission_statuses_arc();
        self.publish_ppoi_workflow_projection(status, submissions);
    }

    pub(crate) fn ppoi_workflow_status(&self) -> WalletPpoiWorkflowStatus {
        *self.sender.borrow().ppoi_workflow_status()
    }

    pub(crate) fn publish_terminal(&self, reason: WalletInactiveReason, reset_generation: u64) {
        let status = self.ppoi_workflow_status().cleared();
        let observation = WalletObservation::with_ppoi_workflow_projection(
            WalletViewState::Inactive {
                reason,
                reset_generation,
            },
            WalletReadiness::Shutdown,
            status,
            Arc::from([]),
        );
        self.sender.send_replace(observation);
    }
}
