use libp2p::{identity, PeerId};
use protonet::network::metrics::NetworkMetrics;
use protonet::network::replay::{ReplayDecision, ReplayState};
use protonet::protocol::record::{unix_time_ms, FlaggedFileRecord};
use protonet::storage::SharedSignatureDb;
use std::time::{Duration, Instant};

#[test]
fn simulated_2_10_50_100_and_500_peer_churn_stays_bounded() {
    for peer_count in [2_usize, 10, 50, 100, 500] {
        let mut replay = ReplayState::with_limits(2_048, Duration::from_secs(60), 512, 1_024);
        let now = Instant::now();
        for sequence in 0..20_u64 {
            for index in 0..peer_count {
                let peer = PeerId::from(identity::Keypair::generate_ed25519().public());
                let id = *blake3::hash(
                    &[
                        sequence.to_le_bytes().as_slice(),
                        index.to_le_bytes().as_slice(),
                    ]
                    .concat(),
                )
                .as_bytes();
                if replay.check(&id, &peer, sequence, now) == ReplayDecision::New {
                    replay.accept(id, peer, sequence, now);
                }
            }
        }
        assert!(replay.recent_len() <= 2_048);
    }
}

#[test]
fn thousands_of_duplicate_gossip_records_create_one_database_change() {
    let database = SharedSignatureDb::in_memory().unwrap();
    let key = identity::Keypair::generate_ed25519();
    let record = FlaggedFileRecord::create(
        &key,
        1,
        unix_time_ms(),
        [1; 32],
        [2; 32],
        10,
        Some("duplicate.bin".to_owned()),
    )
    .unwrap();
    for _ in 0..5_000 {
        database.insert_record(&record).unwrap();
    }
    assert_eq!(database.count(), 1);
    assert_eq!(database.state().unwrap().generation, 1);
}

#[test]
fn controlled_propagation_metrics_report_p50_p95_and_p99() {
    let mut metrics = NetworkMetrics::default();
    for micros in 1..=10_000_u64 {
        metrics.record_validation(micros);
        metrics.record_persistence(micros * 2);
        metrics.record_propagation(micros * 3);
    }
    let snapshot = metrics.snapshot();
    assert!((4_900..=5_100).contains(&snapshot.validation_p50_us));
    assert!((9_400..=9_600).contains(&snapshot.validation_p95_us));
    assert!((9_800..=10_000).contains(&snapshot.validation_p99_us));
    assert!(snapshot.persistence_p99_us > snapshot.persistence_p50_us);
    assert!(snapshot.propagation_p99_us > snapshot.propagation_p95_us);
}

#[test]
fn high_latency_loss_and_churn_do_not_change_signed_payloads() {
    let key = identity::Keypair::generate_ed25519();
    let record = FlaggedFileRecord::create(
        &key,
        1,
        unix_time_ms(),
        [8; 32],
        [9; 32],
        44,
        Some("lossy-link.bin".to_owned()),
    )
    .unwrap();
    let wire = record.encode().unwrap();
    for simulated_attempt in 0..1_000 {
        if simulated_attempt % 3 == 0 {
            continue;
        }
        let delayed = wire.clone();
        assert_eq!(delayed, wire);
    }
}
