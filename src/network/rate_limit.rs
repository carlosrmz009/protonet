use crate::network::limits::{
    GOSSIP_BYTES_PER_MINUTE, GOSSIP_RECORDS_PER_MINUTE, INVALID_MESSAGES_PER_MINUTE,
    MAX_TRACKED_RATE_PEERS, SYNC_REQUESTS_PER_MINUTE, SYNC_RESPONSE_BYTES_PER_HOUR,
};
use libp2p::PeerId;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    updated: Instant,
}

impl Bucket {
    fn new(capacity: u64, period: Duration, now: Instant) -> Self {
        Self {
            tokens: capacity as f64,
            capacity: capacity as f64,
            refill_per_second: capacity as f64 / period.as_secs_f64(),
            updated: now,
        }
    }

    fn take(&mut self, amount: usize, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_second).min(self.capacity);
        self.updated = now;
        if self.tokens < amount as f64 {
            return false;
        }
        self.tokens -= amount as f64;
        true
    }
}

struct PeerBuckets {
    gossip_records: Bucket,
    gossip_bytes: Bucket,
    sync_requests: Bucket,
    sync_response_bytes: Bucket,
    invalid: Bucket,
}

impl PeerBuckets {
    fn new(now: Instant) -> Self {
        Self {
            gossip_records: Bucket::new(GOSSIP_RECORDS_PER_MINUTE, Duration::from_secs(60), now),
            gossip_bytes: Bucket::new(GOSSIP_BYTES_PER_MINUTE, Duration::from_secs(60), now),
            sync_requests: Bucket::new(SYNC_REQUESTS_PER_MINUTE, Duration::from_secs(60), now),
            sync_response_bytes: Bucket::new(
                SYNC_RESPONSE_BYTES_PER_HOUR,
                Duration::from_secs(60 * 60),
                now,
            ),
            invalid: Bucket::new(INVALID_MESSAGES_PER_MINUTE, Duration::from_secs(60), now),
        }
    }
}

pub struct RateLimiter {
    peers: LruCache<PeerId, PeerBuckets>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            peers: LruCache::new(NonZeroUsize::new(MAX_TRACKED_RATE_PEERS).expect("non-zero")),
        }
    }
}

impl RateLimiter {
    fn peer(&mut self, peer: PeerId, now: Instant) -> &mut PeerBuckets {
        self.peers.get_or_insert_mut(peer, || PeerBuckets::new(now))
    }

    pub fn allow_gossip(&mut self, peer: PeerId, bytes: usize, now: Instant) -> bool {
        let buckets = self.peer(peer, now);
        buckets.gossip_records.take(1, now) && buckets.gossip_bytes.take(bytes, now)
    }

    pub fn allow_sync_request(&mut self, peer: PeerId, now: Instant) -> bool {
        self.peer(peer, now).sync_requests.take(1, now)
    }

    pub fn allow_sync_response(&mut self, peer: PeerId, bytes: usize, now: Instant) -> bool {
        self.peer(peer, now).sync_response_bytes.take(bytes, now)
    }

    pub fn note_invalid(&mut self, peer: PeerId, now: Instant) -> bool {
        self.peer(peer, now).invalid.take(1, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttles_peer_after_gossip_limit() {
        let mut limiter = RateLimiter::default();
        let peer = PeerId::random();
        let now = Instant::now();
        for _ in 0..GOSSIP_RECORDS_PER_MINUTE {
            assert!(limiter.allow_gossip(peer, 1, now));
        }
        assert!(!limiter.allow_gossip(peer, 1, now));
    }
}
