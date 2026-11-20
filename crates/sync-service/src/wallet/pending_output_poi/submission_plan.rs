#[allow(clippy::wildcard_imports)]
use super::*;

impl PendingOutputPoiSubmissionPlan {
    const fn new(
        predicate: PendingOutputPoiSubmissionPredicate,
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self {
            predicate,
            list_keys,
            expected_recovery,
            force_submission_retry,
        }
    }

    pub(super) const fn missing(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::Missing,
            list_keys,
            expected_recovery,
            false,
        )
    }

    pub(super) const fn retry_submitted(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
        force_submission_retry: bool,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::RetrySubmitted,
            list_keys,
            expected_recovery,
            force_submission_retry,
        )
    }

    /// Force-resubmit plan: active list keys already on the context (submitted or not).
    pub(in crate::wallet) const fn force_matching(
        list_keys: Vec<FixedBytes<32>>,
        expected_recovery: ExpectedRecordState,
    ) -> Self {
        Self::new(
            PendingOutputPoiSubmissionPredicate::ForceMatching,
            list_keys,
            expected_recovery,
            true,
        )
    }

    pub(in crate::wallet) fn retain_current_recoverable(
        &mut self,
        context: &PendingOutputPoiContextRecord,
        active_list_keys: &[FixedBytes<32>],
        poi: Option<&UtxoPoiMetadata>,
    ) {
        self.list_keys = recoverable_pending_submission_list_keys(
            context,
            active_list_keys,
            poi,
            self.predicate(),
        );
    }

    pub(in crate::wallet) fn list_keys(&self) -> &[FixedBytes<32>] {
        &self.list_keys
    }

    pub(in crate::wallet) fn expected_recovery(&self) -> ExpectedRecordState {
        self.expected_recovery.clone()
    }

    pub(in crate::wallet) const fn predicate(&self) -> PendingOutputPoiSubmissionPredicate {
        self.predicate
    }

    pub(super) const fn submit_intent(&self) -> PendingOutputPoiSubmitIntent {
        match self.predicate {
            PendingOutputPoiSubmissionPredicate::Missing => PendingOutputPoiSubmitIntent::Missing,
            PendingOutputPoiSubmissionPredicate::RetrySubmitted => {
                PendingOutputPoiSubmitIntent::RetrySubmitted
            }
            PendingOutputPoiSubmissionPredicate::ForceMatching => {
                PendingOutputPoiSubmitIntent::ForceMatching
            }
        }
    }

    /// How a deferral of this plan stays forced for later passes, if at all.
    pub(super) const fn deferred_force_kind(&self) -> Option<DeferredForceKind> {
        if matches!(
            self.predicate,
            PendingOutputPoiSubmissionPredicate::ForceMatching
        ) {
            Some(DeferredForceKind::ForceMatching)
        } else if self.force_submission_retry {
            Some(DeferredForceKind::RetrySubmitted)
        } else {
            None
        }
    }
}

pub(super) fn recoverable_pending_submission_list_keys(
    context: &PendingOutputPoiContextRecord,
    active_list_keys: &[FixedBytes<32>],
    poi: Option<&UtxoPoiMetadata>,
    predicate: PendingOutputPoiSubmissionPredicate,
) -> Vec<FixedBytes<32>> {
    let submitted_list_keys = &context.submitted_poi_list_keys;
    let mut list_keys = match predicate {
        PendingOutputPoiSubmissionPredicate::Missing => context.missing_list_keys(),
        PendingOutputPoiSubmissionPredicate::RetrySubmitted => context
            .list_keys()
            .into_iter()
            .filter(|list_key| submitted_list_keys.contains(list_key))
            .collect(),
        PendingOutputPoiSubmissionPredicate::ForceMatching => context.list_keys(),
    };
    list_keys.retain(|list_key| {
        active_list_keys.contains(list_key)
            && poi.is_none_or(|poi| {
                poi.statuses
                    .get(list_key)
                    .is_none_or(|status| status.is_recoverable())
            })
    });
    list_keys
}
