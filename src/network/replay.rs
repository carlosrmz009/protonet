use crate::network::limits::{
    MAX_TRACKED_ORIGINS, RECENT_RECORD_CAPACITY, RECENT_RECORD_TTL, SEQUENCE_WINDOW,
};
use crate::protocol::RecordId;
use libp2p::PeerId;
use lru::LruCache;
use std::collections::BTreeSet;
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
        let Some(window) = self.origins.get(origin) else {
            return ReplayDecision::New;
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
        let window = self.origins.get_or_insert_mut(origin, || OriginWindow {
            highest: sequence,
            accepted: BTreeSet::new(),
        });
        window.highest = window.highest.max(sequence);
        window.accepted.insert(sequence);
        let floor = window.highest.saturating_sub(self.sequence_window);
        window.accepted.retain(|value| *value >= floor);
    }

    pub fn recent_len(&self) -> usize {
        self.recently_seen.len()
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
}
