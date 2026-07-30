use crate::protocol::FlaggedFileRecord;
use crate::storage::database::SharedSignatureDb;
use libp2p::PeerId;
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const PERSISTENCE_QUEUE_CAPACITY: usize = 10_000;
const MAX_BATCH: usize = 100;
const MAX_BATCH_DELAY: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub struct PersistRequest {
    pub record: FlaggedFileRecord,
    pub source: Option<PeerId>,
    pub received_at: Instant,
}

#[derive(Debug)]
pub struct PersistEvent {
    pub record: FlaggedFileRecord,
    pub source: Option<PeerId>,
    pub received_at: Instant,
    pub inserted: bool,
    pub persistence_micros: u64,
    pub database_size_bytes: u64,
}

#[derive(Clone)]
pub struct PersistenceHandle {
    pub tx: mpsc::Sender<PersistRequest>,
    depth: Arc<AtomicUsize>,
    saturations: Arc<AtomicU64>,
}

impl PersistenceHandle {
    pub fn spawn(database: SharedSignatureDb) -> (Self, mpsc::Receiver<PersistEvent>) {
        let (tx, mut rx) = mpsc::channel::<PersistRequest>(PERSISTENCE_QUEUE_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel::<PersistEvent>(PERSISTENCE_QUEUE_CAPACITY);
        let depth = Arc::new(AtomicUsize::new(0));
        let saturations = Arc::new(AtomicU64::new(0));
        let worker_depth = depth.clone();
        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(MAX_BATCH);
            loop {
                let first = match rx.recv().await {
                    Some(value) => value,
                    None => break,
                };
                worker_depth.fetch_sub(1, Ordering::Relaxed);
                batch.push(first);
                let deadline = tokio::time::Instant::now() + MAX_BATCH_DELAY;
                while batch.len() < MAX_BATCH {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(value)) => {
                            worker_depth.fetch_sub(1, Ordering::Relaxed);
                            batch.push(value);
                        }
                        _ => break,
                    }
                }

                let started = Instant::now();
                let records: Vec<_> = batch.iter().map(|item| item.record.clone()).collect();
                let results = database.insert_batch(&records);
                let elapsed = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
                let database_size_bytes = database.database_size_bytes();
                for (index, request) in batch.drain(..).enumerate() {
                    let inserted = results
                        .as_ref()
                        .ok()
                        .and_then(|values| values.get(index))
                        .copied()
                        .unwrap_or(false);
                    if event_tx
                        .send(PersistEvent {
                            record: request.record,
                            source: request.source,
                            received_at: request.received_at,
                            inserted,
                            persistence_micros: elapsed,
                            database_size_bytes,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        });
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
            Err(_) => {
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
