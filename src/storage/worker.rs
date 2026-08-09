use crate::protocol::{FlaggedFileRecord, RecordId};
use crate::storage::database::SharedSignatureDb;
use libp2p::PeerId;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    mpsc::{self, SyncSender, TrySendError},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;

pub const PERSISTENCE_QUEUE_CAPACITY: usize = 10_000;
const MAX_BATCH: usize = 100;
const MAX_BATCH_DELAY: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub struct PersistRequest {
    pub record: FlaggedFileRecord,
    pub source: Option<PeerId>,
    pub received_at: Instant,
    pub gossip_validation: Option<(libp2p::gossipsub::MessageId, PeerId)>,
}

#[derive(Debug, Clone)]
pub enum PersistError {
    StorageSafety(String),
    Database(String),
}

#[derive(Debug)]
pub enum PersistEvent {
    Stored {
        record: Box<FlaggedFileRecord>,
        source: Option<PeerId>,
        received_at: Instant,
        persistence_micros: u64,
        database_size_bytes: u64,
        gossip_validation: Option<(libp2p::gossipsub::MessageId, PeerId)>,
    },
    Duplicate {
        record_id: RecordId,
        origin: Option<PeerId>,
        sequence: u64,
        persistence_micros: u64,
        database_size_bytes: u64,
        gossip_validation: Option<(libp2p::gossipsub::MessageId, PeerId)>,
    },
    Failed {
        record_id: RecordId,
        error: PersistError,
        persistence_micros: u64,
        database_size_bytes: u64,
        gossip_validation: Option<(libp2p::gossipsub::MessageId, PeerId)>,
    },
}

#[derive(Clone)]
pub struct PersistenceHandle {
    tx: SyncSender<PersistRequest>,
    depth: Arc<AtomicUsize>,
    saturations: Arc<AtomicU64>,
}

impl PersistenceHandle {
    pub fn spawn(database: SharedSignatureDb) -> (Self, tokio_mpsc::Receiver<PersistEvent>) {
        let (tx, rx) = mpsc::sync_channel::<PersistRequest>(PERSISTENCE_QUEUE_CAPACITY);
        let (event_tx, event_rx) = tokio_mpsc::channel::<PersistEvent>(PERSISTENCE_QUEUE_CAPACITY);
        let depth = Arc::new(AtomicUsize::new(0));
        let saturations = Arc::new(AtomicU64::new(0));
        let worker_depth = depth.clone();
        std::thread::Builder::new()
            .name("protonet-sqlite-writer".to_owned())
            .spawn(move || {
                let mut batch = Vec::with_capacity(MAX_BATCH);
                while let Ok(first) = rx.recv() {
                    worker_depth.fetch_sub(1, Ordering::Relaxed);
                    batch.push(first);
                    let deadline = Instant::now() + MAX_BATCH_DELAY;
                    while batch.len() < MAX_BATCH {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        match rx.recv_timeout(remaining) {
                            Ok(value) => {
                                worker_depth.fetch_sub(1, Ordering::Relaxed);
                                batch.push(value);
                            }
                            Err(_) => break,
                        }
                    }
                    let started = Instant::now();
                    let records: Vec<_> = batch.iter().map(|item| item.record.clone()).collect();
                    let results = database.insert_batch(&records);
                    let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                    let database_size_bytes = database.database_size_bytes();
                    match results {
                        Ok(results) => {
                            for (request, inserted) in batch.drain(..).zip(results) {
                                let event = if inserted {
                                    PersistEvent::Stored {
                                        record: Box::new(request.record),
                                        source: request.source,
                                        received_at: request.received_at,
                                        persistence_micros: elapsed,
                                        database_size_bytes,
                                        gossip_validation: request.gossip_validation,
                                    }
                                } else {
                                    PersistEvent::Duplicate {
                                        record_id: request.record.record_id,
                                        origin: request.record.origin_peer_id().ok(),
                                        sequence: request.record.sequence,
                                        persistence_micros: elapsed,
                                        database_size_bytes,
                                        gossip_validation: request.gossip_validation,
                                    }
                                };
                                if event_tx.blocking_send(event).is_err() {
                                    return;
                                }
                            }
                        }
                        Err(error) => {
                            let text = format!("{error:#}");
                            let error = if text.contains("storage safety mode") {
                                PersistError::StorageSafety(text)
                            } else {
                                PersistError::Database(text)
                            };
                            for request in batch.drain(..) {
                                if event_tx
                                    .blocking_send(PersistEvent::Failed {
                                        record_id: request.record.record_id,
                                        error: error.clone(),
                                        persistence_micros: elapsed,
                                        database_size_bytes,
                                        gossip_validation: request.gossip_validation,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                }
            })
            .expect("failed to start SQLite writer thread");
        (
            Self {
                tx,
                depth,
                saturations,
            },
            event_rx,
        )
    }

    pub fn try_enqueue(&self, request: PersistRequest) -> bool {
        self.depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(request) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.depth.fetch_sub(1, Ordering::Relaxed);
                self.saturations.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn depth(&self) -> usize {
        self.depth.load(Ordering::Relaxed)
    }

    pub fn saturations(&self) -> u64 {
        self.saturations.load(Ordering::Relaxed)
    }
}
