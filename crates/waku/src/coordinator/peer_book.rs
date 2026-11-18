#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const MAX_LEARNED_PEERS: usize = 256;
pub(super) const MAX_ADDRS_PER_PEER: usize = 16;

/// Where a peer book entry came from, weakest first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum PeerSource {
    #[default]
    Learned,
    Dns {
        last_round: u64,
    },
    Configured,
}

impl PeerSource {
    const fn upgraded(self, incoming: Self) -> Self {
        match (self, incoming) {
            (_, Self::Configured) | (Self::Learned, Self::Dns { .. }) => incoming,
            (Self::Dns { last_round: old }, Self::Dns { last_round: new }) => Self::Dns {
                last_round: if new > old { new } else { old },
            },
            (current, _) => current,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct PeerState {
    pub(super) source: PeerSource,
    pub(super) addrs: Vec<Multiaddr>,
    pub(super) connected: bool,
    pub(super) supports_lightpush_v3: bool,
    pub(super) supports_peer_exchange: bool,
    pub(super) supports_filter: bool,
    pub(super) supports_store: bool,
    pub(super) dial_failures: u32,
    pub(super) next_dial_at: Option<Instant>,
    pub(super) last_peer_exchange_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct PeerBook {
    pub(super) peers: HashMap<PeerId, PeerState>,
    pub(super) connected: HashSet<PeerId>,
    pub(super) dialing: HashSet<PeerId>,
}

impl PeerBook {
    /// Get statistics about the current peer state.
    #[must_use]
    pub fn get_stats(&self) -> PeerStats {
        let connected_peers: Vec<PeerId> = self.connected.iter().copied().collect();
        let lightpush_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_lightpush_v3))
            .count();
        let peer_exchange_capable = self
            .connected
            .iter()
            .filter(|p| self.peers.get(p).is_some_and(|s| s.supports_peer_exchange))
            .count();

        PeerStats {
            connected_peers,
            known_peers: self.peers.len(),
            dialing_count: self.dialing.len(),
            lightpush_capable,
            peer_exchange_capable,
        }
    }

    /// Get the list of currently connected peers.
    #[must_use]
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected.iter().copied().collect()
    }

    #[must_use]
    pub fn num_connections(&self) -> usize {
        self.connected.len() + self.dialing.len()
    }

    /// Build a read-only snapshot of every known peer's state.
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peers
            .iter()
            .map(|(peer_id, state)| PeerSnapshot {
                peer_id: *peer_id,
                addrs: state.addrs.clone(),
                connected: self.connected.contains(peer_id),
                dialing: self.dialing.contains(peer_id),
                supports_lightpush_v3: state.supports_lightpush_v3,
                supports_peer_exchange: state.supports_peer_exchange,
                supports_filter: state.supports_filter,
                dial_failures: state.dial_failures,
            })
            .collect()
    }

    /// Whether connected peers cover both `LightPush` v3 and Filter, possibly on different peers.
    pub(super) fn ready(&self) -> bool {
        let any_connected = |supports: fn(&PeerState) -> bool| {
            self.connected
                .iter()
                .any(|peer_id| self.peers.get(peer_id).is_some_and(supports))
        };
        any_connected(|state| state.supports_lightpush_v3)
            && any_connected(|state| state.supports_filter)
    }
}

pub(super) fn record_dial_failure(state: &mut PeerState, now: Instant) {
    state.dial_failures = state.dial_failures.saturating_add(1);
    let pow = state.dial_failures.min(8);
    let backoff = Duration::from_secs(1 << pow);
    state.next_dial_at = Some(now + backoff);
}

pub(super) fn apply_addr_policy(tor: bool, addrs: &mut Vec<Multiaddr>) {
    if tor {
        retain_tor_safe_addrs(addrs);
    } else {
        addrs.sort();
    }
}

/// Keeps the most recently announced addresses, then sorts them by the address policy.
pub(super) fn merge_addrs(addrs: &mut Vec<Multiaddr>, announced: Vec<Multiaddr>, tor: bool) {
    let mut merged = Vec::with_capacity(MAX_ADDRS_PER_PEER);
    for addr in announced.into_iter().chain(std::mem::take(addrs)) {
        if merged.len() == MAX_ADDRS_PER_PEER {
            break;
        }
        if !merged.contains(&addr) {
            merged.push(addr);
        }
    }
    apply_addr_policy(tor, &mut merged);
    *addrs = merged;
}

fn is_idle(book: &PeerBook, peer_id: &PeerId) -> bool {
    !book.connected.contains(peer_id) && !book.dialing.contains(peer_id)
}

/// Evicts idle learned peers without addresses, then those with the most dial failures, until
/// fewer than `MAX_LEARNED_PEERS` remain or nothing is eligible. Returns the learned count.
fn evict_idle_learned_peers(book: &mut PeerBook) -> usize {
    let mut learned = book
        .peers
        .values()
        .filter(|state| state.source == PeerSource::Learned)
        .count();
    while learned >= MAX_LEARNED_PEERS {
        let victim = book
            .peers
            .iter()
            .filter(|(peer_id, state)| {
                state.source == PeerSource::Learned && is_idle(book, peer_id)
            })
            .max_by_key(|(_, state)| (state.addrs.is_empty(), state.dial_failures))
            .filter(|(_, state)| state.addrs.is_empty() || state.dial_failures > 0)
            .map(|(peer_id, _)| *peer_id);
        let Some(victim) = victim else { break };
        book.peers.remove(&victim);
        learned -= 1;
    }
    learned
}

/// Adds or updates a peer. A new learned peer needs a free learned slot. Returns whether the
/// peer is in the book afterwards.
pub(super) fn insert_peer(
    book: &mut PeerBook,
    peer_id: PeerId,
    addrs: Vec<Multiaddr>,
    source: PeerSource,
    tor: bool,
) -> bool {
    if let Some(state) = book.peers.get_mut(&peer_id) {
        state.source = state.source.upgraded(source);
        merge_addrs(&mut state.addrs, addrs, tor);
        return true;
    }
    if source == PeerSource::Learned && evict_idle_learned_peers(book) >= MAX_LEARNED_PEERS {
        debug!(target: LOG_TARGET, %peer_id, "learned peer limit reached, dropping peer");
        return false;
    }
    let mut state = PeerState {
        source,
        ..PeerState::default()
    };
    merge_addrs(&mut state.addrs, addrs, tor);
    book.peers.insert(peer_id, state);
    true
}

/// Removes the least recently discovered idle DNS peers until at most `bound` remain.
pub(super) fn retain_dns_peers(book: &mut PeerBook, bound: usize) {
    let dns = book
        .peers
        .values()
        .filter(|state| matches!(state.source, PeerSource::Dns { .. }))
        .count();
    if dns <= bound {
        return;
    }
    let mut idle = book
        .peers
        .iter()
        .filter_map(|(peer_id, state)| match state.source {
            PeerSource::Dns { last_round } if is_idle(book, peer_id) => {
                Some((last_round, *peer_id))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    idle.sort_unstable_by_key(|(last_round, _)| *last_round);
    for (_, peer_id) in idle.into_iter().take(dns - bound) {
        book.peers.remove(&peer_id);
    }
}

pub(super) fn remap_wrong_peer_id(
    book: &mut PeerBook,
    expected_peer_id: PeerId,
    obtained_peer_id: PeerId,
    address: &Multiaddr,
    now: Instant,
    tor: bool,
) {
    let dialed_addr = without_trailing_peer_id(address);
    let expected_exhausted = book.peers.get_mut(&expected_peer_id).is_some_and(|state| {
        state
            .addrs
            .retain(|addr| without_trailing_peer_id(addr) != dialed_addr);
        record_dial_failure(state, now);
        state.source == PeerSource::Learned && state.addrs.is_empty()
    });
    if expected_exhausted && is_idle(book, &expected_peer_id) {
        book.peers.remove(&expected_peer_id);
    }

    let remapped_addr = with_peer_id(address, obtained_peer_id);
    if let Some(state) = book.peers.get_mut(&obtained_peer_id) {
        state
            .addrs
            .retain(|addr| without_trailing_peer_id(addr) != dialed_addr);
        merge_addrs(&mut state.addrs, vec![remapped_addr], tor);
    } else {
        insert_peer(
            book,
            obtained_peer_id,
            vec![remapped_addr],
            PeerSource::Learned,
            tor,
        );
    }
}
