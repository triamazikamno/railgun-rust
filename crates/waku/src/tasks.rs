//! Tracks the tasks a node spawns so shutdown can wait for all of them to end.

use tokio::sync::mpsc;

/// Cloneable spawner. Every clone and every task spawned through it keeps the tracker open.
#[derive(Clone)]
pub(crate) struct TaskTracker(mpsc::Sender<()>);

/// Observes when every [`TaskTracker`] clone and every tracked task is gone.
pub(crate) struct TaskWaiter(mpsc::Receiver<()>);

pub(crate) fn task_tracker() -> (TaskTracker, TaskWaiter) {
    // No message is ever sent; the channel closes when the last sender drops.
    let (sender, receiver) = mpsc::channel(1);
    (TaskTracker(sender), TaskWaiter(receiver))
}

impl TaskTracker {
    /// Spawn `future` on the Tokio runtime as a tracked task.
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let guard = self.0.clone();
        tokio::spawn(async move {
            let _guard = guard;
            future.await;
        });
    }
}

impl TaskWaiter {
    /// Wait until every tracker clone and tracked task has been dropped. Cancel safe, and
    /// returns immediately once that has been observed.
    pub(crate) async fn wait(&mut self) {
        while self.0.recv().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    #[tokio::test]
    async fn shutdown_waits_for_tracked_work() {
        let (tasks, mut waiter) = task_tracker();
        let (release, held) = oneshot::channel::<()>();
        tasks.spawn(async move {
            let _ = held.await;
        });
        drop(tasks);

        assert!(
            timeout(Duration::from_millis(100), waiter.wait())
                .await
                .is_err(),
            "a running tracked task keeps the waiter pending"
        );

        release.send(()).expect("tracked task is waiting");
        timeout(Duration::from_secs(1), waiter.wait())
            .await
            .expect("waiter completes once tracked work ends");
    }
}
