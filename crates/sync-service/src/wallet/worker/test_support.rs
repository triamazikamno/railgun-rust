use super::*;

pub(in crate::wallet) enum WalletPoiStatusReaderSource<'a> {
    Local(LocalPoiStatusReader),
    Remote(&'a PoiRpcClient),
}

impl WalletPoiStatusReaderSource<'_> {
    pub(in crate::wallet) fn as_reader(&self) -> &dyn PoiStatusReader {
        match self {
            Self::Local(reader) => reader,
            Self::Remote(reader) => *reader,
        }
    }
}

impl WalletPoiRuntime {
    /// Job-only: may return remote proxy / fallback reader.
    pub(in crate::wallet) async fn status_reader_for_job<'a>(
        &'a self,
        public_data_plane: &ChainPublicDataPlane,
        cfg: &WalletConfig,
        active_list_keys: &[FixedBytes<32>],
    ) -> Option<WalletPoiStatusReaderSource<'a>> {
        match self {
            Self::IndexedArtifacts { .. } => {
                let key = PublicPoiCorpusKey::wallet_default(cfg.chain.chain_id);
                if !public_data_plane
                    .poi_corpus_ready_for_lists(key.clone(), active_list_keys)
                    .await
                {
                    return self
                        .wallet_read_fallback_enabled()
                        .then(|| WalletPoiStatusReaderSource::Remote(self.public_client()));
                }
                let corpus = public_data_plane.ensure_poi_corpus(key).await.ok()?;
                Some(WalletPoiStatusReaderSource::Local(corpus.status_reader()))
            }
            Self::PoiProxy { .. } => {
                Some(WalletPoiStatusReaderSource::Remote(self.public_client()))
            }
        }
    }
}

pub(crate) async fn spawn_wallet_worker(
    services: WalletWorkerServices,
    cfg: WalletConfig,
    actor_id: u64,
    live_rx: broadcast::Receiver<SharedLogBatch>,
    backfill_rx: mpsc::Receiver<BackfillEvent>,
    cancel: CancellationToken,
    initial_utxos: Vec<WalletUtxo>,
    initial_last_scanned: u64,
) -> Result<WalletHandle, ChainError> {
    let mut prepared = prepare_wallet_worker(
        services,
        cfg,
        actor_id,
        live_rx,
        backfill_rx,
        cancel,
        initial_utxos,
        initial_last_scanned,
    )
    .await?;
    let worker = prepared.take_worker();
    match prepared.activate() {
        Ok(handle) => {
            drop(worker);
            Ok(handle)
        }
        Err(err) => {
            let _ = worker.await;
            Err(err)
        }
    }
}
