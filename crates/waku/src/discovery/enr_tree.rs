use super::DiscoveredPeer;
use super::enr::decode_enr_record;
use super::error::{DnsResolveError, EnrTreeError};
use super::txt::TxtResolver;
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use rand::rng;
use rand::seq::SliceRandom;
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::sync::OnceLock;

const TREE_PREFIX: &str = "enrtree:";
const ROOT_PREFIX: &str = "enrtree-root:";
const BRANCH_PREFIX: &str = "enrtree-branch:";
const RECORD_PREFIX: &str = "enr:";
const MIN_HASH_LEN: usize = 12;
const MAX_HASH_LEN: usize = 32;

/// TXT lookup used by tree discovery, so tests can serve trees from memory.
pub(super) trait TxtLookup {
    async fn resolve_txt(&self, name: &str) -> Result<Vec<String>, DnsResolveError>;
}

impl TxtLookup for TxtResolver {
    async fn resolve_txt(&self, name: &str) -> Result<Vec<String>, DnsResolveError> {
        Self::resolve_txt(self, name).await
    }
}

#[derive(Debug, Clone)]
struct EnrTreeRef {
    public_key_b32: String,
    domain: String,
    e_root: String,
}

pub(super) async fn discover_from_tree<R: TxtLookup>(
    resolver: &R,
    tree_url: &str,
    max_txt_queries: usize,
    max_enrs: usize,
) -> Result<Vec<DiscoveredPeer>, EnrTreeError> {
    let mut tree_ref = parse_tree(tree_url)?;

    // Root TXT record is stored at the tree domain.
    let root_txt = resolver.resolve_txt(&tree_ref.domain).await?;

    let root_record = root_txt
        .into_iter()
        .find(|s| s.starts_with(ROOT_PREFIX))
        .ok_or_else(|| EnrTreeError::MissingRoot(tree_ref.domain.clone()))?;

    tree_ref.e_root = parse_and_verify_root(&root_record, &tree_ref.public_key_b32)?;

    let mut peers = Vec::new();
    let mut seen_records = HashSet::<String>::new();

    let mut total_queries = 0;
    let mut empty_or_duplicate = 0;

    while peers.len() < max_enrs && total_queries < max_txt_queries {
        let (maybe_record, used_queries) = random_walk_one_record(resolver, &tree_ref, 64).await?;
        total_queries += used_queries;

        let Some(record) = maybe_record else {
            empty_or_duplicate += 1;
            if empty_or_duplicate > 50 {
                break;
            }
            continue;
        };

        if seen_records.contains(&record) {
            empty_or_duplicate += 1;
            continue;
        }

        seen_records.insert(record.clone());

        if let Ok(peer) = decode_enr_record(&record) {
            peers.push(peer);
        }

        // Stop if the tree isn't yielding anything new.
        if empty_or_duplicate > 50 {
            break;
        }
    }

    Ok(peers)
}

async fn random_walk_one_record<R: TxtLookup>(
    resolver: &R,
    tree: &EnrTreeRef,
    max_steps: usize,
) -> Result<(Option<String>, usize), EnrTreeError> {
    let mut current = tree.e_root.clone();
    let mut visited = HashSet::<String>::new();
    let mut queries = 0;

    for _ in 0..max_steps {
        queries += 1;

        let location = format!("{current}.{}", tree.domain);

        let txt_records = resolver.resolve_txt(&location).await.unwrap_or_default();
        if txt_records.is_empty() {
            return Ok((None, queries));
        }

        // Each record is checked on its own, so a forged extra record cannot hide the genuine one.
        let hash = decode_hash_label(&current)?;
        let entry = txt_records
            .into_iter()
            .find(|record| Keccak256::digest(record.as_bytes()).starts_with(&hash))
            .ok_or(EnrTreeError::HashMismatch)?;

        if entry.starts_with(BRANCH_PREFIX) {
            let mut branches = parse_branch(&entry)?;
            branches.shuffle(&mut rng());

            // Prefer unvisited branches to reduce loops.
            let next = branches
                .iter()
                .find(|b| !visited.contains(*b))
                .cloned()
                .or_else(|| branches.first().cloned());

            let Some(next) = next else {
                return Ok((None, queries));
            };

            visited.insert(current);
            current = next;
            continue;
        }

        if entry.starts_with(RECORD_PREFIX) {
            return Ok((Some(entry), queries));
        }

        // Unknown entry, or a root below the tree domain, which is never followed.
        return Ok((None, queries));
    }

    Ok((None, queries))
}

fn parse_tree(tree: &str) -> Result<EnrTreeRef, EnrTreeError> {
    if !tree.starts_with(TREE_PREFIX) {
        return Err(EnrTreeError::InvalidTreeUrlPrefix);
    }

    let without_prefix = tree
        .strip_prefix("enrtree://")
        .ok_or(EnrTreeError::InvalidTreeUrlPrefix)?;

    let (public_key_b32, domain) = without_prefix
        .split_once('@')
        .ok_or(EnrTreeError::InvalidTreeUrlFormat)?;

    Ok(EnrTreeRef {
        public_key_b32: public_key_b32.to_string(),
        domain: domain.to_string(),
        e_root: String::new(),
    })
}

fn parse_and_verify_root(root: &str, public_key_b32: &str) -> Result<String, EnrTreeError> {
    if !root.starts_with(ROOT_PREFIX) {
        return Err(EnrTreeError::InvalidRootPrefix);
    }

    let root_values = parse_root_values(root)?;
    decode_hash_label(&root_values.e_root)?;

    let public_key_bytes = BASE32_NOPAD.decode(public_key_b32.as_bytes())?;

    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)?;

    // Signature is 65 bytes (recovery id at end). Verify uses compact 64-byte signature.
    let sig_bytes =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(root_values.signature)?;

    if sig_bytes.len() < 64 {
        return Err(EnrTreeError::InvalidSignatureLength);
    }

    let signature = Signature::from_slice(&sig_bytes[..64])?;

    let signed_component = root
        .split(" sig")
        .next()
        .ok_or(EnrTreeError::InvalidRootFormat)?;

    let mut hasher = Keccak256::new();
    hasher.update(signed_component.as_bytes());
    let digest = hasher.finalize();

    verifying_key
        .verify_prehash(digest.as_ref(), &signature)
        .map_err(|_| EnrTreeError::SignatureVerificationFailed)?;

    Ok(root_values.e_root)
}

#[derive(Debug)]
struct RootValues {
    e_root: String,
    signature: String,
}

fn parse_root_values(txt: &str) -> Result<RootValues, EnrTreeError> {
    static ROOT_RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = ROOT_RE.get_or_init(|| {
        regex::Regex::new(r"^enrtree-root:v1 e=([^ ]+) l=([^ ]+) seq=(\d+) sig=([^ ]+)$")
            .expect("valid ENR tree root regex")
    });

    let caps = re.captures(txt).ok_or(EnrTreeError::InvalidRootFormat)?;

    let e_root = caps
        .get(1)
        .ok_or(EnrTreeError::InvalidRootFormat)?
        .as_str()
        .to_string();

    let signature = caps
        .get(4)
        .ok_or(EnrTreeError::InvalidRootFormat)?
        .as_str()
        .to_string();

    Ok(RootValues { e_root, signature })
}

fn parse_branch(branch: &str) -> Result<Vec<String>, EnrTreeError> {
    if !branch.starts_with(BRANCH_PREFIX) {
        return Err(EnrTreeError::InvalidBranchPrefix);
    }

    let suffix = branch
        .strip_prefix(BRANCH_PREFIX)
        .ok_or(EnrTreeError::InvalidBranchPrefix)?;

    if suffix.is_empty() {
        return Ok(Vec::new());
    }

    suffix
        .split(',')
        .map(|label| decode_hash_label(label).map(|_| label.to_string()))
        .collect()
}

/// Decodes an entry label. Unused trailing bits are ignored, as Go's decoder in Geth does, but
/// malformed lengths are still rejected.
fn decode_hash_label(label: &str) -> Result<Vec<u8>, EnrTreeError> {
    static LABEL_BASE32: OnceLock<data_encoding::Encoding> = OnceLock::new();
    let base32 = LABEL_BASE32.get_or_init(|| {
        let mut spec = BASE32_NOPAD.specification();
        spec.check_trailing_bits = false;
        spec.encoding().expect("valid ENR tree label base32")
    });

    base32
        .decode(label.as_bytes())
        .ok()
        .filter(|hash| (MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash.len()))
        .ok_or(EnrTreeError::InvalidHash)
}

#[cfg(test)]
pub(super) mod fixture {
    use super::{BRANCH_PREFIX, ROOT_PREFIX, TxtLookup};
    use crate::discovery::DnsResolveError;
    use base64::Engine;
    use data_encoding::BASE32_NOPAD;
    use enr::k256::ecdsa::signature::hazmat::PrehashSigner;
    use enr::k256::ecdsa::{Signature, SigningKey};
    use sha3::{Digest, Keccak256};
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    impl TxtLookup for HashMap<String, Vec<String>> {
        fn resolve_txt(
            &self,
            name: &str,
        ) -> impl Future<Output = Result<Vec<String>, DnsResolveError>> {
            std::future::ready(Ok(self.get(name).cloned().unwrap_or_default()))
        }
    }

    /// An in-memory DNS tree signed with a fixed test key.
    pub(crate) struct TestTree {
        pub(crate) url: String,
        pub(crate) records: HashMap<String, Vec<String>>,
        domain: String,
        hash_len: usize,
        key: SigningKey,
    }

    impl TestTree {
        pub(crate) fn new(domain: &str, hash_len: usize) -> Self {
            let key = SigningKey::from_slice(&[7; 32]).expect("test tree key");
            let public_key = key.verifying_key().to_encoded_point(true);
            Self {
                url: format!(
                    "enrtree://{}@{domain}",
                    BASE32_NOPAD.encode(public_key.as_bytes())
                ),
                records: HashMap::new(),
                domain: domain.to_string(),
                hash_len,
                key,
            }
        }

        pub(crate) fn name(&self, label: &str) -> String {
            format!("{label}.{}", self.domain)
        }

        /// Publishes `text` at its content-hash label and returns the label.
        pub(crate) fn publish(&mut self, text: &str) -> String {
            let label = BASE32_NOPAD.encode(&Keccak256::digest(text.as_bytes())[..self.hash_len]);
            self.records
                .insert(self.name(&label), vec![text.to_string()]);
            label
        }

        pub(crate) fn branch(&mut self, children: &[String]) -> String {
            self.publish(&format!("{BRANCH_PREFIX}{}", children.join(",")))
        }

        pub(crate) fn root_text(&self, e_label: &str) -> String {
            let signed = format!("{ROOT_PREFIX}v1 e={e_label} l={e_label} seq=1");
            let signature: Signature = self
                .key
                .sign_prehash(&Keccak256::digest(signed.as_bytes()))
                .expect("sign test root");
            let mut sig = signature.to_bytes().to_vec();
            sig.push(0);
            format!(
                "{signed} sig={}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
            )
        }

        pub(crate) fn set_root(&mut self, e_label: &str) {
            let root = self.root_text(e_label);
            self.records.insert(self.domain.clone(), vec![root]);
        }
    }

    /// A signed root pointing at one branch with two ENR leaves; returns the branch and leaf labels.
    pub(crate) fn genuine_tree(domain: &str, hash_len: usize) -> (TestTree, String, [String; 2]) {
        let mut tree = TestTree::new(domain, hash_len);
        let leaves = [tree.publish(&test_enr(1)), tree.publish(&test_enr(2))];
        let branch = tree.branch(&leaves);
        tree.set_root(&branch);
        (tree, branch, leaves)
    }

    /// A Waku ENR for a peer derived from `seed`. Signatures are randomized, so each call differs.
    pub(crate) fn test_enr(seed: u8) -> String {
        let key = SigningKey::from_slice(&[seed; 32]).expect("test ENR key");
        enr::Enr::<SigningKey>::builder()
            .ip4(Ipv4Addr::new(10, 0, 0, seed))
            .tcp4(60000)
            .add_value("waku2", &[1_u8].as_slice())
            .build(&key)
            .expect("test ENR")
            .to_base64()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{TestTree, genuine_tree, test_enr};
    use super::*;
    use crate::discovery::{DEFAULT_CLEARNET_DOH_ENDPOINT, RAILGUN_TREE};

    async fn discover(tree: &TestTree) -> Result<Vec<DiscoveredPeer>, EnrTreeError> {
        discover_from_tree(&tree.records, &tree.url, 400, 200).await
    }

    #[tokio::test]
    async fn entries_must_match_their_labels_at_each_hash_length() {
        for hash_len in [12, 16, 20, 32] {
            let (tree, _, _) = genuine_tree("tree.example", hash_len);
            let peers = discover(&tree).await.expect("genuine tree");
            assert_eq!(peers.len(), 2, "hash length {hash_len}");

            let (mut tree, branch, leaves) = genuine_tree("tree.example", hash_len);
            let name = tree.name(&branch);
            tree.records
                .insert(name, vec![format!("{BRANCH_PREFIX}{}", leaves[0])]);
            let result = discover(&tree).await;
            assert!(
                matches!(result, Err(EnrTreeError::HashMismatch)),
                "hash length {hash_len}: {result:?}"
            );

            let (mut tree, _, leaves) = genuine_tree("tree.example", hash_len);
            let name = tree.name(&leaves[1]);
            tree.records.insert(name, vec![test_enr(3)]);
            let result = discover(&tree).await;
            assert!(
                matches!(result, Err(EnrTreeError::HashMismatch)),
                "hash length {hash_len}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_child_labels_abort_tree() {
        let valid = BASE32_NOPAD.encode(&[0_u8; 16]);
        let cases = [
            vec![BASE32_NOPAD.encode(&[0_u8; 11])],
            vec![BASE32_NOPAD.encode(&[0_u8; 33])],
            vec!["not-base32".to_string()],
            vec![valid.clone(), String::new(), valid],
        ];
        for children in cases {
            let mut tree = TestTree::new("tree.example", 16);
            let branch = tree.branch(&children);
            tree.set_root(&branch);
            let result = discover(&tree).await;
            assert!(
                matches!(result, Err(EnrTreeError::InvalidHash)),
                "{children:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn empty_branches_end_walks_without_failing() {
        let mut tree = TestTree::new("tree.example", 16);
        let empty = tree.branch(&[]);
        tree.set_root(&empty);
        assert!(discover(&tree).await.expect("empty tree").is_empty());

        let mut tree = TestTree::new("tree.example", 16);
        let leaves = [tree.publish(&test_enr(1)), tree.publish(&test_enr(2))];
        let empty = tree.branch(&[]);
        let branch = tree.branch(&[leaves[0].clone(), leaves[1].clone(), empty]);
        tree.set_root(&branch);
        assert_eq!(
            discover(&tree)
                .await
                .expect("tree with empty subtree")
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn genuine_record_is_used_beside_a_forged_one() {
        let (mut tree, _, leaves) = genuine_tree("tree.example", 16);
        let name = tree.name(&leaves[0]);
        let forged = test_enr(3);
        let forged_peer = decode_enr_record(&forged).expect("forged ENR").peer_id;
        tree.records
            .get_mut(&name)
            .expect("leaf record")
            .insert(0, forged);
        let peers = discover(&tree).await.expect("tree");
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|peer| peer.peer_id != forged_peer));
    }

    #[tokio::test]
    async fn labels_with_nonzero_unused_trailing_bits_are_followed() {
        let mut tree = TestTree::new("tree.example", 16);
        let text = test_enr(1);
        let canonical = BASE32_NOPAD.encode(&Keccak256::digest(text.as_bytes())[..16]);
        // 16 bytes fill 26 symbols with 2 unused low bits in the last one; set them.
        let symbols = BASE32_NOPAD.specification().symbols;
        let last = symbols
            .find(&canonical[25..])
            .expect("canonical last symbol");
        let altered = format!(
            "{}{}",
            &canonical[..25],
            char::from(symbols.as_bytes()[last | 0b11])
        );
        let expected = decode_enr_record(&text).expect("leaf ENR").peer_id;
        // Served only at the altered name, so the walk must query the label as published.
        let name = tree.name(&altered);
        tree.records.insert(name, vec![text]);
        let branch = tree.branch(&[altered]);
        tree.set_root(&branch);

        let peers = discover(&tree).await.expect("tree");
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer_id, expected);
    }

    #[tokio::test]
    async fn root_below_tree_domain_ends_walk() {
        let mut tree = TestTree::new("tree.example", 16);
        let leaf = tree.publish(&test_enr(1));
        let inner_root = tree.root_text(&leaf);
        let inner_root = tree.publish(&inner_root);
        let branch = tree.branch(&[inner_root]);
        tree.set_root(&branch);
        assert!(discover(&tree).await.expect("tree").is_empty());
    }

    #[tokio::test]
    #[ignore = "resolves the live Railgun tree through public DoH"]
    async fn live_railgun_tree_passes_hash_checks() {
        let resolver = TxtResolver::new_with_endpoints(
            vec![DEFAULT_CLEARNET_DOH_ENDPOINT.to_string()],
            None,
            false,
        )
        .expect("resolver");
        let peers = discover_from_tree(&resolver, RAILGUN_TREE, 400, 200)
            .await
            .expect("live tree discovery");
        eprintln!("live Railgun tree peers: {}", peers.len());
        assert!(!peers.is_empty());
    }
}
