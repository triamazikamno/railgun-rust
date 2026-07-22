use super::{WalletConfig, warn};

pub(super) fn log_local_poi_cache_unavailable(cfg: &WalletConfig, reason: &'static str) {
    warn!(
        chain_id = cfg.chain.chain_id,
        reason, "artifact POI local cache unavailable; skipping local POI refresh"
    );
}

#[cfg(test)]
pub(super) mod test_support {
    use alloy::primitives::FixedBytes;
    use poi::cache::PoiCache;

    use crate::types::WalletLocalPoiCaches;

    pub(in crate::wallet) async fn install_tailed_poi_cache_if_current(
        local_caches: &WalletLocalPoiCaches,
        list_key: FixedBytes<32>,
        cache: PoiCache,
        expected_next_event_index: u64,
    ) -> bool {
        let mut caches = local_caches.write().await;
        let Some(current) = caches.get(&list_key) else {
            return false;
        };
        if current.progress().next_event_index != expected_next_event_index {
            return false;
        }
        caches.insert(list_key, cache);
        true
    }
}
