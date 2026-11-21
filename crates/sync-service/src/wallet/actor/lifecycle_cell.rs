#[allow(clippy::wildcard_imports)]
use super::*;

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

    /// Moves a current Prepared/Active actor to Stopping and performs its one terminal
    /// publication while holding the lifecycle fence.
    pub(crate) fn publish_terminal_shutdown_if_allowed(
        &self,
        is_current: bool,
        publish: impl for<'a> FnOnce(WalletActorTerminalToken<'a>),
    ) -> bool {
        self.with_fence(|inner| {
            if is_current
                && matches!(
                    inner.state,
                    WalletActorLifecycle::Prepared | WalletActorLifecycle::Active
                )
            {
                inner.state = WalletActorLifecycle::Stopping;
            }
            let publish_blocked = !inner.state.allows_terminal_shutdown_publish()
                || inner.terminal_shutdown_published
                || !is_current;
            if publish_blocked {
                return false;
            }
            inner.terminal_shutdown_published = true;
            publish(WalletActorTerminalToken {
                _fence: PhantomData,
            });
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

#[cfg(test)]
impl WalletActorLifecycleCell {
    /// Prepared/Active → Stopping. Returns true if this call performed the transition.
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
}
