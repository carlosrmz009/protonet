use crate::network::connection_manager::{Directness, TransportKind};
use crate::network::limits::MAX_NETWORK_COMMANDS;
use crate::network::metrics::MetricsSnapshot;
use crate::protocol::RecordId;
use crate::storage::SharedSignatureDb;
use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub enum NetworkCommand {
    PublishFile {
        sha256: [u8; 32],
        blake3: [u8; 32],
        file_size: u64,
        file_name: Option<String>,
    },
    Connect(Multiaddr),
    Disconnect(PeerId),
    AddBootstrapPeer(PeerId, Multiaddr),
    RemoveBootstrapPeer(PeerId),
    RequestSync(PeerId),
    RequestSyncAny,
    ResetIdentity,
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Started {
        peer_id: PeerId,
    },
    IdentityReset {
        peer_id: PeerId,
    },
    Listening {
        address: Multiaddr,
    },
    PeerConnected {
        peer_id: PeerId,
        address: Multiaddr,
        directness: Directness,
        transport: TransportKind,
    },
    PeerDisconnected {
        peer_id: PeerId,
    },
    RelayReservation {
        relay_peer_id: PeerId,
    },
    RecordReceived {
        record_id: RecordId,
        from: PeerId,
        file_name: Option<String>,
    },
    RecordPublished {
        record_id: RecordId,
        file_name: Option<String>,
    },
    SyncStarted {
        peer_id: PeerId,
    },
    SyncProgress {
        peer_id: PeerId,
        received: u64,
    },
    SyncCompleted {
        peer_id: PeerId,
        received: u64,
    },
    ProtocolViolation {
        peer_id: Option<PeerId>,
        reason: String,
    },
    ReachabilityChanged {
        state: Reachability,
    },
    StorageSafetyChanged {
        active: bool,
        reason: Option<String>,
    },
    LogMessage(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reachability {
    Public,
    Private,
    #[default]
    Unknown,
}

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub peer_id: PeerId,
    pub address: Multiaddr,
    pub directness: Directness,
    pub transport: TransportKind,
    pub round_trip_time: Option<Duration>,
    pub protocol_version: Option<String>,
    pub records_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkSnapshot {
    pub local_peer_id: Option<PeerId>,
    pub peers: Vec<PeerSnapshot>,
    pub listen_addresses: Vec<Multiaddr>,
    pub reachability: Reachability,
    pub dht_status: String,
    pub gossipsub_mesh_size: usize,
    pub persistence_queue_depth: usize,
    pub replay_cache_size: usize,
    pub database_size_bytes: u64,
    pub database_records: usize,
    pub storage_safety_mode: bool,
    pub storage_safety_reason: Option<String>,
    pub metrics: MetricsSnapshot,
}

#[derive(Clone)]
pub struct P2pHandle {
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    snapshot: Arc<RwLock<NetworkSnapshot>>,
}

impl P2pHandle {
    pub fn peer_count(&self) -> usize {
        self.snapshot.read().peers.len()
    }

    pub fn local_peer_id(&self) -> Option<PeerId> {
        self.snapshot.read().local_peer_id
    }

    pub fn snapshot(&self) -> NetworkSnapshot {
        self.snapshot.read().clone()
    }

    pub fn get_peers_info(&self) -> Vec<PeerSnapshot> {
        self.snapshot.read().peers.clone()
    }
}

pub struct P2pEngine;

impl P2pEngine {
    pub async fn spawn(
        config: crate::network::NetworkConfig,
        database: SharedSignatureDb,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> anyhow::Result<P2pHandle> {
        config.validate()?;
        let store = crate::identity::IdentityStore::new(config.identity_path.clone());
        let identity = store.load_or_create()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(MAX_NETWORK_COMMANDS);
        let snapshot = Arc::new(RwLock::new(NetworkSnapshot {
            local_peer_id: Some(identity.peer_id),
            dht_status: "initializing".to_owned(),
            database_records: database.count(),
            database_size_bytes: database.database_size_bytes(),
            ..NetworkSnapshot::default()
        }));
        let handle = P2pHandle {
            cmd_tx,
            snapshot: snapshot.clone(),
        };
        tokio::spawn(async move {
            if let Err(error) = crate::network::swarm::run_engine(
                config,
                store,
                identity,
                database,
                cmd_rx,
                event_tx.clone(),
                snapshot,
            )
            .await
            {
                let _ = event_tx.try_send(NetworkEvent::ProtocolViolation {
                    peer_id: None,
                    reason: format!("network task stopped: {error:#}"),
                });
            }
        });
        Ok(handle)
    }

    pub fn event_channel() -> (mpsc::Sender<NetworkEvent>, mpsc::Receiver<NetworkEvent>) {
        mpsc::channel(1024)
    }
}
