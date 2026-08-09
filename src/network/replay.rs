use crate::network::limits::{
    MAX_TRACKED_ORIGINS, RECENT_RECORD_CAPACITY, RECENT_RECORD_TTL, SEQUENCE_WINDOW,
};
use crate::protocol::RecordId;
use libp2p::PeerId;
use lru::LruCache;
use std::collections::{BTreeSet, HashMap};
use std::num::NonZeroUsize;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDecision {
    New,
    Duplicate,
    TooOld,
}

#[derive(Debug)]
struct OriginWindow {
    highest: u64,
    accepted: BTreeSet<u64>,
}

pub struct ReplayState {
    recently_seen: LruCache<RecordId, Instant>,
    origins: LruCache<PeerId, OriginWindow>,
    persistent_highest: HashMap<PeerId, u64>,
    active_records: ActiveRecordFilter,
    ttl: std::time::Duration,
    sequence_window: u64,
}

impl Default for ReplayState {
    fn default() -> Self {
        Self::with_limits(
            RECENT_RECORD_CAPACITY,
            RECENT_RECORD_TTL,
            MAX_TRACKED_ORIGINS,
            SEQUENCE_WINDOW,
        )
    }
}

impl ReplayState {
    pub fn with_limits(
        records: usize,
        ttl: std::time::Duration,
        origins: usize,
        sequence_window: u64,
    ) -> Self {
        Self {
            recently_seen: LruCache::new(NonZeroUsize::new(records.max(1)).expect("non-zero")),
            origins: LruCache::new(NonZeroUsize::new(origins.max(1)).expect("non-zero")),
            persistent_highest: HashMap::new(),
            active_records: ActiveRecordFilter::new(16 * 1024 * 1024),
            ttl,
            sequence_window,
        }
    }

    pub fn check(
        &mut self,
        record_id: &RecordId,
        origin: &PeerId,
        sequence: u64,
        now: Instant,
    ) -> ReplayDecision {
        if let Some(seen_at) = self.recently_seen.get(record_id).copied() {
            if now.saturating_duration_since(seen_at) <= self.ttl {
                return ReplayDecision::Duplicate;
            }
            self.recently_seen.pop(record_id);
        }
        if self.active_records.contains(record_id) {
            return ReplayDecision::Duplicate;
        }
        let Some(window) = self.origins.get(origin) else {
            return match self.persistent_highest.get(origin) {
                Some(highest) if sequence.saturating_add(self.sequence_window) <= *highest => {
                    ReplayDecision::TooOld
                }
                _ => ReplayDecision::New,
            };
        };
        if window.accepted.contains(&sequence) {
            return ReplayDecision::Duplicate;
        }
        if sequence.saturating_add(self.sequence_window) <= window.highest {
            return ReplayDecision::TooOld;
        }
        ReplayDecision::New
    }

    pub fn accept(&mut self, record_id: RecordId, origin: PeerId, sequence: u64, now: Instant) {
        self.recently_seen.put(record_id, now);
        self.active_records.insert(&record_id);
        self.persistent_highest
            .entry(origin)
            .and_modify(|highest| *highest = (*highest).max(sequence))
            .or_insert(sequence);
        let window = self.origins.get_or_insert_mut(origin, || OriginWindow {
            highest: sequence,
            accepted: BTreeSet::new(),
        });
        window.highest = window.highest.max(sequence);
        window.accepted.insert(sequence);
        let floor = window.highest.saturating_sub(self.sequence_window);
        window.accepted.retain(|value| *value >= floor);
    }

    pub fn mark_pending(&mut self, record_id: RecordId, now: Instant) {
        self.recently_seen.put(record_id, now);
    }

    pub fn forget(&mut self, record_id: &RecordId) {
        self.recently_seen.pop(record_id);
    }

    pub fn recent_len(&self) -> usize {
        self.recently_seen.len()
    }

    pub fn load_persistent_state(
        &mut self,
        origins: impl IntoIterator<Item = (PeerId, u64)>,
        active_ids: impl IntoIterator<Item = RecordId>,
    ) {
        self.persistent_highest = origins.into_iter().collect();
        for id in active_ids {
            self.active_records.insert(&id);
        }
    }
}

struct ActiveRecordFilter {
    bits: Vec<u64>,
}

impl ActiveRecordFilter {
    fn new(bytes: usize) -> Self {
        Self {
            bits: vec![0; bytes.max(8) / 8],
        }
    }

    fn insert(&mut self, id: &RecordId) {
        for index in self.indices(id) {
            self.bits[index / 64] |= 1_u64 << (index % 64);
        }
    }

    fn contains(&self, id: &RecordId) -> bool {
        self.indices(id)
            .into_iter()
            .all(|index| self.bits[index / 64] & (1_u64 << (index % 64)) != 0)
    }

    fn indices(&self, id: &RecordId) -> [usize; 4] {
        let modulus = self.bits.len() * 64;
        let value = |offset: usize| {
            u64::from_le_bytes(id[offset..offset + 8].try_into().expect("fixed record ID")) as usize
                % modulus
        };
        [value(0), value(8), value(16), value(24)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn duplicate_cache_and_origin_tracking_are_bounded() {
        let mut state = ReplayState::with_limits(4, Duration::from_secs(10), 2, 4);
        let now = Instant::now();
        let peer = PeerId::random();
        for value in 0..1_000_u64 {
            let id = *blake3::hash(&value.to_le_bytes()).as_bytes();
            state.accept(id, peer, value, now);
        }
        assert_eq!(state.recent_len(), 4);
        let newest = *blake3::hash(&999_u64.to_le_bytes()).as_bytes();
        assert_eq!(
            state.check(&newest, &peer, 999, now),
            ReplayDecision::Duplicate
        );
        let old = *blake3::hash(b"unseen-old").as_bytes();
        assert_eq!(state.check(&old, &peer, 1, now), ReplayDecision::TooOld);
    }

    #[test]
    fn bounded_window_allows_limited_out_of_order_records() {
        let mut state = ReplayState::with_limits(10, Duration::from_secs(10), 2, 1_024);
        let peer = PeerId::random();
        let now = Instant::now();
        state.accept([1; 32], peer, 1_000, now);
        assert_eq!(state.check(&[2; 32], &peer, 999, now), ReplayDecision::New);
    }

    #[test]
    fn persistent_membership_and_highest_sequences_survive_memory_eviction() {
        let peer = PeerId::random();
        let mut state = ReplayState::with_limits(1, Duration::from_secs(1), 1, 10);
        state.load_persistent_state([(peer, 1_000)], [[7; 32]]);
        assert_eq!(
            state.check(&[7; 32], &PeerId::random(), 50_000, Instant::now()),
            ReplayDecision::Duplicate
        );
        assert_eq!(
            state.check(&[8; 32], &peer, 1, Instant::now()),
            ReplayDecision::TooOld
        );
    }
}
