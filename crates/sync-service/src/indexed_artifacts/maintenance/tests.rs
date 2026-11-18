use super::*;

#[tokio::test]
async fn maintenance_shutdown_cancels_running_work_and_rejects_admission() {
    struct DropSignal(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }

    let scheduler = IndexedArtifactMaintenanceScheduler::with_capacity(1);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (dropped_tx, mut dropped_rx) = tokio::sync::oneshot::channel();
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(1), 1, async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        },),
        IndexedArtifactMaintenanceAdmission::Admitted
    );
    started_rx.await.expect("maintenance job started");
    assert_eq!(
        scheduler.try_schedule(
            IndexedArtifactMaintenanceKey::Test(1),
            1,
            std::future::pending(),
        ),
        IndexedArtifactMaintenanceAdmission::Duplicate
    );
    assert_eq!(
        scheduler.try_schedule(
            IndexedArtifactMaintenanceKey::Test(2),
            1,
            std::future::pending(),
        ),
        IndexedArtifactMaintenanceAdmission::Admitted
    );
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(3), 1, async {},),
        IndexedArtifactMaintenanceAdmission::Full
    );
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(3), 1, async {},),
        IndexedArtifactMaintenanceAdmission::Full,
        "a failed send must release its keyed reservation"
    );

    scheduler.shutdown().await;

    dropped_rx
        .try_recv()
        .expect("shutdown awaited the worker's maintenance drop signal");
    {
        let admission = scheduler
            .inner
            .admission
            .lock()
            .expect("maintenance admission state after shutdown");
        assert_eq!(admission.retained_payload_bytes, 0);
        assert_eq!(admission.keys, [] as [IndexedArtifactMaintenanceKey; 0]);
    }
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(4), 1, async {},),
        IndexedArtifactMaintenanceAdmission::Shutdown
    );
}

#[tokio::test]
async fn maintenance_payload_cap_releases_after_job_completion() {
    let scheduler = IndexedArtifactMaintenanceScheduler::with_limits(2, 10);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(1), 6, async move {
            let _ = started_tx.send(());
            let _ = release_rx.await;
        },),
        IndexedArtifactMaintenanceAdmission::Admitted
    );
    started_rx.await.expect("payload-holding job started");

    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(2), 5, async {},),
        IndexedArtifactMaintenanceAdmission::PayloadFull,
        "the count queue still has capacity, but the aggregate byte cap rejects"
    );

    let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(3), 0, async move {
            let _ = drained_tx.send(());
        },),
        IndexedArtifactMaintenanceAdmission::Admitted
    );
    release_tx.send(()).expect("release payload-holding job");
    drained_rx.await.expect("payload reservation released");
    let (admitted_tx, admitted_rx) = tokio::sync::oneshot::channel();
    assert_eq!(
        scheduler.try_schedule(IndexedArtifactMaintenanceKey::Test(2), 5, async move {
            let _ = admitted_tx.send(());
        },),
        IndexedArtifactMaintenanceAdmission::Admitted
    );
    admitted_rx.await.expect("post-release job ran");
    scheduler.shutdown().await;
}
