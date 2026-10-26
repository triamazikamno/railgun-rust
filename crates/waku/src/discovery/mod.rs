pub(crate) mod enr;
mod enr_tree;
mod error;
mod txt;

pub use error::{DiscoveryError, DnsResolveError, EnrDecodeError, EnrTreeError};

use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::Duration;

pub const SANDBOX_ENR_TREE: &str =
    "enrtree://AIRVQ5DDA4FFWLRBCHJWUWOO6X6S4ZTZ5B667LQ6AJU6PEYDLRD5O@sandbox.waku.nodes.status.im";
pub const TEST_ENR_TREE: &str =
    "enrtree://AOGYWMBYOUIMOENHXCHILPKY3ZRFEULMFI4DOM442QSZ73TT2A7VI@test.waku.nodes.status.im";
pub const RAILGUN_TREE: &str =
    "enrtree://APMYHUVNQWHJNPI5L2KQ765EMCKUAMRWPUH3U2QIKPK6XEV3OW442@discovery.rootedinprivacy.com";
pub const DEFAULT_CLEARNET_DOH_ENDPOINT: &str = "https://cloudflare-dns.com/dns-query";
pub const DEFAULT_TOR_DOH_ENDPOINT: &str =
    "https://dns4torpnlfs2ifuz2s2yf3fc7rdmsbhm6rw75euj35pac6ap25zgqad.onion/dns-query";

#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
}

#[derive(Clone)]
pub struct DiscoveryConfig {
    pub enr_trees: Vec<String>,
    pub max_txt_queries_per_tree: usize,
    pub max_enrs_per_tree: usize,
    pub doh_endpoint: String,
    pub doh_fallback_endpoints: Vec<String>,
    pub http_client: Option<reqwest::Client>,
    pub allow_system_dns: bool,
    pub dns_discovery_interval: Duration,
    pub peer_exchange_interval: Duration,
    pub peer_exchange_rounds: usize,
    pub peer_exchange_bootstrap_interval: Duration,
    pub peer_exchange_bootstrap_peers: usize,
}

impl std::fmt::Debug for DiscoveryConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryConfig")
            .field("enr_trees", &self.enr_trees)
            .field("max_txt_queries_per_tree", &self.max_txt_queries_per_tree)
            .field("max_enrs_per_tree", &self.max_enrs_per_tree)
            .field("doh_endpoint", &self.doh_endpoint)
            .field("doh_fallback_endpoints", &self.doh_fallback_endpoints)
            .field("http_client", &self.http_client.is_some())
            .field("allow_system_dns", &self.allow_system_dns)
            .field("dns_discovery_interval", &self.dns_discovery_interval)
            .field("peer_exchange_interval", &self.peer_exchange_interval)
            .field("peer_exchange_rounds", &self.peer_exchange_rounds)
            .field(
                "peer_exchange_bootstrap_interval",
                &self.peer_exchange_bootstrap_interval,
            )
            .field(
                "peer_exchange_bootstrap_peers",
                &self.peer_exchange_bootstrap_peers,
            )
            .finish()
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enr_trees: vec![RAILGUN_TREE.to_string()],
            max_txt_queries_per_tree: 400,
            max_enrs_per_tree: 200,
            doh_endpoint: DEFAULT_CLEARNET_DOH_ENDPOINT.to_string(),
            doh_fallback_endpoints: Vec::new(),
            http_client: None,
            allow_system_dns: true,
            dns_discovery_interval: Duration::from_mins(30),
            peer_exchange_interval: Duration::from_mins(1),
            peer_exchange_rounds: 3,
            peer_exchange_bootstrap_interval: Duration::from_secs(10),
            peer_exchange_bootstrap_peers: 3,
        }
    }
}

impl DiscoveryConfig {
    fn doh_endpoints(&self) -> Vec<String> {
        let mut endpoints = Vec::with_capacity(1 + self.doh_fallback_endpoints.len());
        endpoints.push(self.doh_endpoint.clone());
        for endpoint in &self.doh_fallback_endpoints {
            if !endpoints.iter().any(|existing| existing == endpoint) {
                endpoints.push(endpoint.clone());
            }
        }
        endpoints
    }

    /// Discover peers from DNS ENR trees.
    pub(crate) async fn discover_all(&self) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        let resolver = txt::TxtResolver::new_with_endpoints(
            self.doh_endpoints(),
            self.http_client.clone(),
            self.allow_system_dns,
        )?;
        self.discover_with(&resolver).await
    }

    async fn discover_with<R: enr_tree::TxtLookup>(
        &self,
        resolver: &R,
    ) -> Result<Vec<DiscoveredPeer>, DiscoveryError> {
        let mut peers = HashMap::<PeerId, Vec<Multiaddr>>::new();
        let mut any_succeeded = false;
        let mut last_error = None;

        for tree in &self.enr_trees {
            match enr_tree::discover_from_tree(
                resolver,
                tree,
                self.max_txt_queries_per_tree,
                self.max_enrs_per_tree,
            )
            .await
            {
                Ok(found) => {
                    any_succeeded = true;
                    for peer in found {
                        peers.entry(peer.peer_id).or_default().extend(peer.addrs);
                    }
                }
                Err(error) => {
                    tracing::warn!(tree = %tree, %error, "dns discovery tree failed");
                    last_error = Some(error);
                }
            }
        }

        if !any_succeeded && let Some(error) = last_error {
            return Err(DiscoveryError::EnrTree(error));
        }

        Ok(peers
            .into_iter()
            .map(|(peer_id, mut addrs)| {
                addrs.sort();
                addrs.dedup();
                DiscoveredPeer { peer_id, addrs }
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enr_tree::fixture::genuine_tree;

    #[tokio::test]
    async fn failed_tree_does_not_drop_other_trees() {
        let (mut tampered, branch, leaves) = genuine_tree("tampered.example", 16);
        let name = tampered.name(&branch);
        tampered
            .records
            .insert(name, vec![format!("enrtree-branch:{}", leaves[0])]);
        let (genuine, _, _) = genuine_tree("genuine.example", 16);

        let mut records = tampered.records;
        records.extend(genuine.records);
        let mut config = DiscoveryConfig {
            enr_trees: vec![tampered.url, genuine.url],
            ..DiscoveryConfig::default()
        };
        let peers = config
            .discover_with(&records)
            .await
            .expect("genuine tree peers");
        assert_eq!(peers.len(), 2);

        config.enr_trees.truncate(1);
        let error = config
            .discover_with(&records)
            .await
            .expect_err("only tree failed");
        assert!(matches!(
            error,
            DiscoveryError::EnrTree(EnrTreeError::HashMismatch)
        ));
    }
}
