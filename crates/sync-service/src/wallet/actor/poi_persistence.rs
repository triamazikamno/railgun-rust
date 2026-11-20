#[allow(clippy::wildcard_imports)]
use super::*;

impl WalletPoiPersistenceRequirements {
    pub(super) const fn is_empty(&self) -> bool {
        !self.required
            && !self.required_or_recoverable
            && self.recoverable_stale.is_none()
            && !self.recoverable
            && self.corpus_revision.is_none()
    }

    pub(super) fn insert(&mut self, reset_generation: u64, selection: WalletPoiRefreshSelection) {
        if self.is_empty() {
            self.reset_generation = Some(reset_generation);
        }
        if self.reset_generation != Some(reset_generation) {
            return;
        }
        match selection {
            WalletPoiRefreshSelection::Required => self.required = true,
            WalletPoiRefreshSelection::RequiredOrRecoverable => {
                self.required_or_recoverable = true;
            }
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                self.recoverable_stale =
                    Some(self.recoverable_stale.map_or(now, |old| old.max(now)));
            }
            WalletPoiRefreshSelection::Recoverable => self.recoverable = true,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => {
                self.corpus_revision =
                    Some(self.corpus_revision.is_some_and(|old| old) || blocked_shields_changed);
            }
        }
    }

    pub(super) fn remove(
        &mut self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        if self.reset_generation != Some(reset_generation) {
            return false;
        }
        let removed = match selection {
            WalletPoiRefreshSelection::Required => std::mem::take(&mut self.required),
            WalletPoiRefreshSelection::RequiredOrRecoverable => {
                std::mem::take(&mut self.required_or_recoverable)
            }
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                let covered = self
                    .recoverable_stale
                    .is_some_and(|required| now >= required);
                if covered {
                    self.recoverable_stale = None;
                }
                covered
            }
            WalletPoiRefreshSelection::Recoverable => std::mem::take(&mut self.recoverable),
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => {
                let covered = self
                    .corpus_revision
                    .is_some_and(|required| !required || blocked_shields_changed);
                if covered {
                    self.corpus_revision = None;
                }
                covered
            }
        };
        if self.is_empty() {
            self.reset_generation = None;
        }
        removed
    }

    pub(super) fn contains(
        &self,
        reset_generation: u64,
        selection: WalletPoiRefreshSelection,
    ) -> bool {
        if self.reset_generation != Some(reset_generation) {
            return false;
        }
        match selection {
            WalletPoiRefreshSelection::Required => self.required,
            WalletPoiRefreshSelection::RequiredOrRecoverable => self.required_or_recoverable,
            WalletPoiRefreshSelection::RecoverableStale { now } => {
                self.recoverable_stale == Some(now)
            }
            WalletPoiRefreshSelection::Recoverable => self.recoverable,
            WalletPoiRefreshSelection::CorpusRevision {
                blocked_shields_changed,
            } => self.corpus_revision == Some(blocked_shields_changed),
        }
    }

    pub(super) fn next(&self, reset_generation: u64) -> Option<WalletPoiRefreshSelection> {
        if self.reset_generation != Some(reset_generation) {
            return None;
        }
        if self.required {
            Some(WalletPoiRefreshSelection::Required)
        } else if self.required_or_recoverable {
            Some(WalletPoiRefreshSelection::RequiredOrRecoverable)
        } else if let Some(now) = self.recoverable_stale {
            Some(WalletPoiRefreshSelection::RecoverableStale { now })
        } else if self.recoverable {
            Some(WalletPoiRefreshSelection::Recoverable)
        } else {
            self.corpus_revision.map(|blocked_shields_changed| {
                WalletPoiRefreshSelection::CorpusRevision {
                    blocked_shields_changed,
                }
            })
        }
    }

    pub(super) const fn rebase(&mut self, reset_generation: u64) {
        if !self.is_empty() {
            self.reset_generation = Some(reset_generation);
        }
    }
}
