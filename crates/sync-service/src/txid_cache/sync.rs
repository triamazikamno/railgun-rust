use super::*;

impl TxidPublicCache<'_> {
    #[cfg(test)]
    pub(crate) async fn sync(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
    ) -> Result<(), TxidPublicCacheError> {
        self.sync_inner(Some(endpoint), http_client, latest, None, false)
            .await
    }

    pub(crate) async fn sync_with_artifact_source(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        railgun_contract: &str,
        latest: TxidPublicLatestValidated,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<(), TxidPublicCacheError> {
        let (artifact_from_index, force_validated_refresh) = {
            let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
            let mut manifest = self.load_or_new_manifest()?;
            let progress_reconciled = manifest.reconcile_validated_progress_for_latest(latest);
            let local_status = manifest.local_latest_status(self.db, latest)?;
            if local_status == TxidPublicLocalLatestStatus::Satisfied {
                if progress_reconciled || !manifest.latest_validated_matches(latest) {
                    manifest.set_latest_validated(latest);
                    manifest.write_to(self.db, self.key)?;
                }
                debug!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    latest_validated_txid_index = latest.txid_index,
                    "TXID public cache already covers latest validated range"
                );
                return Ok(());
            }
            (
                manifest.artifact_fetch_start_index(latest, local_status),
                local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh,
            )
        };
        let artifact_chunks = match indexed_artifact_source {
            Some(config) => match self
                .fetch_artifact_chunks_for_range(
                    railgun_contract,
                    config,
                    http_client,
                    artifact_from_index,
                    Some(latest.txid_index),
                )
                .await
            {
                Ok(chunks) if !chunks.is_empty() => Some(chunks),
                Ok(_) => None,
                Err(err) if endpoint.is_some() => {
                    warn!(
                        ?err,
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        "TXID public cache artifact chunks unavailable; falling back to GraphQL"
                    );
                    None
                }
                Err(err) => return Err(err),
            },
            None => None,
        };

        self.sync_inner(
            endpoint,
            http_client,
            latest,
            artifact_chunks.as_deref(),
            force_validated_refresh,
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn sync_with_artifact_chunks(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        artifact_chunks: Option<&[crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
    ) -> Result<(), TxidPublicCacheError> {
        self.sync_inner(Some(endpoint), http_client, latest, artifact_chunks, false)
            .await
    }

    async fn sync_inner(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        latest: TxidPublicLatestValidated,
        artifact_chunks: Option<&[crate::indexed_artifacts::VerifiedIndexedArtifactChunk]>,
        force_validated_refresh: bool,
    ) -> Result<(), TxidPublicCacheError> {
        let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let started = std::time::Instant::now();
        let mut manifest = self.load_or_new_manifest()?;
        if force_validated_refresh {
            manifest.validated_cached_txid_index = None;
        } else {
            manifest.reconcile_validated_progress_for_latest(latest);
        }
        if !force_validated_refresh {
            manifest.set_latest_validated(latest);
        }
        if !force_validated_refresh
            && manifest.local_latest_status(self.db, latest)?
                == TxidPublicLocalLatestStatus::Satisfied
        {
            manifest.write_to(self.db, self.key)?;
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                latest_validated_txid_index = latest.txid_index,
                validated_cached_txid_index = ?manifest.validated_cached_txid_index,
                "TXID public cache already covers latest validated range after artifact fetch"
            );
            return Ok(());
        }

        let mut fetched_rows = 0_u64;
        if let Some(chunks) = artifact_chunks.filter(|chunks| !chunks.is_empty()) {
            if let Some(applied_rows) = manifest.apply_artifact_chunks_with_progress_guard(
                self.db,
                self.key,
                chunks,
                Some(latest.txid_index),
                latest.merkleroot,
                endpoint.is_some(),
            )? {
                fetched_rows = fetched_rows.saturating_add(applied_rows);
            }
        } else {
            debug!(
                chain_id = self.key.chain_id,
                txid_version = self.key.txid_version,
                graphql_available = endpoint.is_some(),
                "TXID public cache artifact chunks unavailable"
            );
        }

        let refresh_start = manifest
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1));
        let refresh_needed = refresh_start <= latest.txid_index;
        let graph_needed = refresh_needed || manifest.next_txid_index <= latest.txid_index;
        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?manifest.validated_cached_txid_index,
            next_txid_index = manifest.next_txid_index,
            refresh_start,
            refresh_needed,
            "TXID public cache sync started"
        );
        let client = if graph_needed {
            match endpoint {
                Some(endpoint) => Some(match http_client.cloned() {
                    Some(http_client) => {
                        QuickSyncClient::with_http_client(endpoint.clone(), http_client)
                    }
                    None => QuickSyncClient::new(endpoint.clone()),
                }),
                None => {
                    debug!(
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        refresh_start,
                        latest_validated_txid_index = latest.txid_index,
                        "TXID public cache needs more rows but GraphQL fallback is unavailable"
                    );
                    None
                }
            }
        } else {
            None
        };
        if refresh_needed && let Some(client) = client.as_ref() {
            let refresh = manifest
                .refresh_validated_range(
                    self.db,
                    client,
                    self.key,
                    refresh_start,
                    latest.txid_index,
                )
                .await?;
            fetched_rows = fetched_rows.saturating_add(refresh.fetched_rows);
            if let Some(refreshed_to) = refresh.refreshed_to {
                manifest.validated_cached_txid_index = Some(refreshed_to);
            }
        }
        while !refresh_needed && manifest.next_txid_index <= latest.txid_index {
            let Some(client) = client.as_ref() else {
                break;
            };
            let start_index = manifest.next_txid_index;
            let page_started = std::time::Instant::now();
            let rows = client
                .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
                .await?;
            if rows.is_empty() {
                break;
            }
            let row_count = rows.len() as u64;
            let page = TxidPublicCachePage::from_indexed_transactions(start_index, rows);
            manifest.insert_or_replace_page(self.db, self.key, &page)?;
            rebuild_index_for_manifest(&manifest, self.db, self.key)?;
            manifest.validated_cached_txid_index = Some(start_index.saturating_add(row_count - 1));
            fetched_rows = fetched_rows.saturating_add(row_count);
            debug!(
                chain_id = self.key.chain_id,
                start_index,
                row_count,
                latest_validated_txid_index = latest.txid_index,
                validated_cached_txid_index = ?manifest.validated_cached_txid_index,
                next_txid_index = manifest.next_txid_index,
                fetched_rows,
                page_elapsed_ms = page_started.elapsed().as_millis(),
                "TXID public cache page synced"
            );
            if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
                break;
            }
        }

        if force_validated_refresh {
            match manifest.local_latest_status(self.db, latest)? {
                TxidPublicLocalLatestStatus::Satisfied => manifest.set_latest_validated(latest),
                TxidPublicLocalLatestStatus::NeedsRows
                | TxidPublicLocalLatestStatus::NeedsValidatedRefresh => {
                    return Err(TxidPublicCacheError::RootMismatch);
                }
            }
        }

        manifest.write_to(self.db, self.key)?;
        info!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            latest_validated_txid_index = latest.txid_index,
            validated_cached_txid_index = ?manifest.validated_cached_txid_index,
            next_txid_index = manifest.next_txid_index,
            fetched_rows,
            refresh_start,
            refresh_needed,
            elapsed_ms = started.elapsed().as_millis(),
            "TXID public cache sync complete"
        );
        Ok(())
    }

    pub(crate) async fn sync_to_graph_tip(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
    ) -> Result<u64, TxidPublicCacheError> {
        let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let started = std::time::Instant::now();
        let mut manifest = self.load_or_new_manifest()?;
        let client = match http_client.cloned() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
            None => QuickSyncClient::new(endpoint.clone()),
        };

        let mut fetched_rows = 0_u64;
        loop {
            let start_index = manifest.next_txid_index;
            let page_started = std::time::Instant::now();
            let rows = client
                .fetch_public_txid_page(start_index, TXID_CACHE_PAGE_SIZE)
                .await?;
            if rows.is_empty() {
                break;
            }
            let row_count = rows.len() as u64;
            let page = TxidPublicCachePage::from_indexed_transactions(start_index, rows);
            manifest.append_page(self.db, self.key, &page)?;
            update_index_for_page(self.db, self.key, &page)?;
            fetched_rows = fetched_rows.saturating_add(row_count);
            debug!(
                chain_id = self.key.chain_id,
                start_index,
                row_count,
                next_txid_index = manifest.next_txid_index,
                fetched_rows,
                page_elapsed_ms = page_started.elapsed().as_millis(),
                "TXID public cache background page synced"
            );
            if row_count < TXID_CACHE_PAGE_SIZE.get() as u64 {
                break;
            }
        }

        manifest.write_to(self.db, self.key)?;
        debug!(
            chain_id = self.key.chain_id,
            txid_version = self.key.txid_version,
            next_txid_index = manifest.next_txid_index,
            fetched_rows,
            elapsed_ms = started.elapsed().as_millis(),
            "TXID public cache background sync complete"
        );
        Ok(fetched_rows)
    }

    pub(crate) async fn sync_to_indexed_tip(
        &self,
        endpoint: Option<&Url>,
        http_client: Option<&reqwest::Client>,
        railgun_contract: &str,
        indexed_artifact_source: Option<&IndexedArtifactSourceConfig>,
    ) -> Result<u64, TxidPublicCacheError> {
        if let Some(config) = indexed_artifact_source {
            let from_index = self
                .load_or_new_manifest()?
                .validated_cached_txid_index
                .map_or(0, |index| index.saturating_add(1));
            match self
                .fetch_artifact_chunks_for_range(
                    railgun_contract,
                    config,
                    http_client,
                    from_index,
                    None,
                )
                .await
            {
                Ok(chunks) if !chunks.is_empty() => {
                    match self
                        .apply_artifact_chunks_only(&chunks, endpoint.is_some())
                        .await?
                    {
                        Some(applied_rows) if applied_rows > 0 => return Ok(applied_rows),
                        Some(_) | None if endpoint.is_none() => return Ok(0),
                        Some(_) | None => {}
                    }
                }
                Ok(_) if endpoint.is_none() => return Ok(0),
                Ok(_) => {}
                Err(err) if endpoint.is_some() => {
                    warn!(
                        ?err,
                        chain_id = self.key.chain_id,
                        txid_version = self.key.txid_version,
                        "TXID public cache background artifact sync unavailable; falling back to GraphQL"
                    );
                }
                Err(err) => return Err(err),
            }
        }

        match endpoint {
            Some(endpoint) => self.sync_to_graph_tip(endpoint, http_client).await,
            None => Ok(0),
        }
    }

    #[cfg(test)]
    pub(super) async fn sync_until_recovered_output_with_page_size(
        &self,
        endpoint: &Url,
        http_client: Option<&reqwest::Client>,
        tx_hash: FixedBytes<32>,
        output_commitment: FixedBytes<32>,
        page_size: NonZeroUsize,
    ) -> Result<TxidPublicCachedTransaction, TxidPublicCacheError> {
        let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let started = std::time::Instant::now();
        let mut manifest = self.load_or_new_manifest()?;
        match find_public_recovery_transaction_in_manifest(
            &manifest,
            self.db,
            self.key,
            tx_hash,
            output_commitment,
        ) {
            Ok(row) => return Ok(row.into()),
            Err(TxidPublicCacheError::MissingTarget) => {}
            Err(err) => return Err(err),
        }
        let client = match http_client.cloned() {
            Some(http_client) => QuickSyncClient::with_http_client(endpoint.clone(), http_client),
            None => QuickSyncClient::new(endpoint.clone()),
        };

        let mut next_index = manifest
            .validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1))
            .min(manifest.next_txid_index);
        let mut fetched_rows = 0_u64;
        loop {
            let start_index = next_index;
            let rows = client
                .fetch_public_txid_page(start_index, page_size)
                .await?;
            if rows.is_empty() {
                manifest.write_to(self.db, self.key)?;
                return Err(TxidPublicCacheError::MissingTarget);
            }
            let row_count = rows.len() as u64;
            let page = TxidPublicCachePage::from_indexed_transactions(start_index, rows);
            if start_index < manifest.next_txid_index {
                manifest.insert_or_replace_page(self.db, self.key, &page)?;
                rebuild_index_for_manifest(&manifest, self.db, self.key)?;
            } else {
                manifest.append_page(self.db, self.key, &page)?;
                update_index_for_page(self.db, self.key, &page)?;
            }
            next_index = start_index.saturating_add(row_count);
            fetched_rows = fetched_rows.saturating_add(row_count);
            manifest.write_to(self.db, self.key)?;
            debug!(
                chain_id = self.key.chain_id,
                start_index,
                row_count,
                next_txid_index = manifest.next_txid_index,
                "TXID public cache recovery page synced"
            );

            if let Some(row) =
                find_target_row_in_page(&manifest, &page, tx_hash, output_commitment)?
            {
                info!(
                    chain_id = self.key.chain_id,
                    txid_version = self.key.txid_version,
                    target_txid_index = row.txid_index,
                    fetched_rows,
                    elapsed_ms = started.elapsed().as_millis(),
                    "TXID public cache recovery target synced"
                );
                return Ok(row.into());
            }
            if row_count < page_size.get() as u64 {
                return Err(TxidPublicCacheError::MissingTarget);
            }
        }
    }

    pub(crate) fn cached_latest_validated(
        &self,
    ) -> Result<Option<TxidPublicLatestValidated>, TxidPublicCacheError> {
        let Some(manifest) = self.load_manifest()? else {
            return Ok(None);
        };
        manifest.validate_for(self.key)?;
        Ok(manifest
            .latest_validated_txid_index
            .map(|txid_index| TxidPublicLatestValidated {
                txid_index,
                merkleroot: manifest.latest_validated_merkleroot,
            }))
    }

    #[cfg(test)]
    pub(crate) async fn put_latest_validated(
        &self,
        latest: TxidPublicLatestValidated,
    ) -> Result<(), TxidPublicCacheError> {
        let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let mut manifest = self.load_or_new_manifest()?;
        manifest.set_latest_validated(latest);
        manifest.write_to(self.db, self.key)
    }

    async fn fetch_artifact_chunks_for_range(
        &self,
        railgun_contract: &str,
        config: &IndexedArtifactSourceConfig,
        http_client: Option<&reqwest::Client>,
        from_index: u64,
        to_index: Option<u64>,
    ) -> Result<Vec<crate::indexed_artifacts::VerifiedIndexedArtifactChunk>, TxidPublicCacheError>
    {
        let scope = self.key.artifact_scope(railgun_contract)?;
        artifact::fetch_txid_public_artifact_chunks(
            config,
            http_client,
            &scope,
            from_index,
            to_index,
        )
        .await
    }

    async fn apply_artifact_chunks_only(
        &self,
        chunks: &[crate::indexed_artifacts::VerifiedIndexedArtifactChunk],
        graphql_fallback_available: bool,
    ) -> Result<Option<u64>, TxidPublicCacheError> {
        let _guard = TXID_CACHE_SYNC_LOCK.lock().await;
        let mut manifest = self.load_or_new_manifest()?;
        manifest.apply_artifact_chunks_with_progress_guard(
            self.db,
            self.key,
            chunks,
            None,
            None,
            graphql_fallback_available,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxidPublicLocalLatestStatus {
    Satisfied,
    NeedsRows,
    NeedsValidatedRefresh,
}

impl TxidPublicCacheManifest {
    fn set_latest_validated(&mut self, latest: TxidPublicLatestValidated) {
        self.latest_validated_txid_index = Some(latest.txid_index);
        self.latest_validated_merkleroot = latest.merkleroot;
    }

    fn latest_validated_matches(&self, latest: TxidPublicLatestValidated) -> bool {
        self.latest_validated_txid_index == Some(latest.txid_index)
            && self.latest_validated_merkleroot == latest.merkleroot
    }

    fn reconcile_validated_progress_for_latest(
        &mut self,
        latest: TxidPublicLatestValidated,
    ) -> bool {
        let previous = self.validated_cached_txid_index;
        if self
            .latest_validated_txid_index
            .is_some_and(|index| index > latest.txid_index)
        {
            if self
                .validated_cached_txid_index
                .is_some_and(|index| index > latest.txid_index)
            {
                self.validated_cached_txid_index = Some(latest.txid_index);
            }
        } else if self.latest_validated_txid_index == Some(latest.txid_index)
            && self.latest_validated_merkleroot != latest.merkleroot
        {
            self.validated_cached_txid_index = None;
        }
        self.validated_cached_txid_index != previous
    }

    fn local_latest_status(
        &self,
        db: &DbStore,
        latest: TxidPublicLatestValidated,
    ) -> Result<TxidPublicLocalLatestStatus, TxidPublicCacheError> {
        if self
            .validated_cached_txid_index
            .is_none_or(|index| index < latest.txid_index)
        {
            return Ok(TxidPublicLocalLatestStatus::NeedsRows);
        }
        let Some(expected_root) = latest.merkleroot else {
            return Ok(TxidPublicLocalLatestStatus::Satisfied);
        };
        let tree = latest.txid_index / TREE_LEAF_COUNT;
        let leaf_count = latest.txid_index % TREE_LEAF_COUNT + 1;
        let leaves = match read_tree_leaves(self, db, tree, leaf_count) {
            Ok(leaves) => leaves,
            Err(TxidPublicCacheError::MissingLeaf { .. }) => {
                return Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh);
            }
            Err(err) => return Err(err),
        };
        let actual_root = DenseMerkleTree::from_ordered_leaves(leaves, leaf_count).root();
        if FixedBytes::from(actual_root.to_be_bytes::<32>()) == expected_root {
            Ok(TxidPublicLocalLatestStatus::Satisfied)
        } else {
            Ok(TxidPublicLocalLatestStatus::NeedsValidatedRefresh)
        }
    }

    fn artifact_fetch_start_index(
        &self,
        latest: TxidPublicLatestValidated,
        local_status: TxidPublicLocalLatestStatus,
    ) -> u64 {
        if local_status == TxidPublicLocalLatestStatus::NeedsValidatedRefresh
            || self.validated_progress_is_stale(latest)
        {
            return 0;
        }
        self.validated_cached_txid_index
            .map_or(0, |index| index.saturating_add(1))
    }

    fn validated_progress_is_stale(&self, latest: TxidPublicLatestValidated) -> bool {
        self.latest_validated_txid_index
            .is_some_and(|index| index > latest.txid_index)
            || (self.latest_validated_txid_index == Some(latest.txid_index)
                && self.latest_validated_merkleroot != latest.merkleroot)
    }

    fn apply_artifact_chunks_with_progress_guard(
        &mut self,
        db: &DbStore,
        key: TxidPublicCacheKey<'_>,
        chunks: &[crate::indexed_artifacts::VerifiedIndexedArtifactChunk],
        to_index: Option<u64>,
        latest_validated_merkleroot: Option<FixedBytes<32>>,
        graphql_fallback_available: bool,
    ) -> Result<Option<u64>, TxidPublicCacheError> {
        let artifact_started = std::time::Instant::now();
        let previous_progress = self.validated_cached_txid_index;
        let mut artifact_manifest = self.clone();
        match artifact_manifest.apply_artifact_chunks_bounded(
            db,
            key,
            chunks,
            to_index,
            latest_validated_merkleroot,
        ) {
            Ok(applied_rows) => {
                *self = artifact_manifest;
                self.write_to(db, key)?;
                if applied_rows > 0 {
                    rebuild_index_for_manifest(self, db, key)?;
                }
                info!(
                    chain_id = key.chain_id,
                    txid_version = key.txid_version,
                    applied_rows,
                    validated_cached_txid_index = ?self.validated_cached_txid_index,
                    elapsed_ms = artifact_started.elapsed().as_millis(),
                    "TXID public cache artifact chunks applied"
                );
                Ok(Some(applied_rows))
            }
            Err(err)
                if self.validated_cached_txid_index == previous_progress
                    && graphql_fallback_available =>
            {
                warn!(
                    ?err,
                    chain_id = key.chain_id,
                    txid_version = key.txid_version,
                    validated_cached_txid_index = ?previous_progress,
                    elapsed_ms = artifact_started.elapsed().as_millis(),
                    "TXID public cache artifact sync failed before progress; falling back to GraphQL"
                );
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    async fn refresh_validated_range(
        &mut self,
        db: &DbStore,
        client: &QuickSyncClient,
        key: TxidPublicCacheKey<'_>,
        start_index: u64,
        end_index: u64,
    ) -> Result<TxidPublicCacheRefresh, TxidPublicCacheError> {
        let mut fetched_rows = 0_u64;
        let mut refreshed_to = None;
        let mut next_index = start_index;
        let started = std::time::Instant::now();
        while next_index <= end_index {
            let page_started = std::time::Instant::now();
            let remaining = end_index.saturating_sub(next_index).saturating_add(1);
            let limit =
                NonZeroUsize::new(remaining.min(TXID_CACHE_PAGE_SIZE.get() as u64) as usize)
                    .expect("validated TXID refresh limit is non-zero");
            let rows = client.fetch_public_txid_page(next_index, limit).await?;
            if rows.is_empty() {
                break;
            }
            let row_count = rows.len() as u64;
            let page = TxidPublicCachePage::from_indexed_transactions(next_index, rows);
            self.insert_or_replace_page(db, key, &page)?;
            fetched_rows = fetched_rows.saturating_add(row_count);
            refreshed_to = Some(next_index.saturating_add(row_count - 1));
            debug!(
                chain_id = key.chain_id,
                start_index = next_index,
                row_count,
                fetched_rows,
                refreshed_to = ?refreshed_to,
                end_index,
                remaining_rows = end_index.saturating_sub(refreshed_to.unwrap_or(next_index)),
                next_txid_index = self.next_txid_index,
                page_elapsed_ms = page_started.elapsed().as_millis(),
                elapsed_ms = started.elapsed().as_millis(),
                "TXID public cache validated page refreshed"
            );
            next_index = next_index.saturating_add(row_count);
            if row_count < limit.get() as u64 {
                break;
            }
        }
        if fetched_rows > 0 {
            rebuild_index_for_manifest(self, db, key)?;
        }
        Ok(TxidPublicCacheRefresh {
            fetched_rows,
            refreshed_to,
        })
    }
}
