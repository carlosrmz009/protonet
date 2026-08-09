use crate::identity::{IdentityStore, StoredIdentity};
use crate::network::behaviour::{BehaviourEvent, ProtonetBehaviour};
use crate::network::config::{peer_from_address, prefer_quic, NetworkConfig, MAX_ADDRESS_BYTES};
use crate::network::connection_manager::ConnectionManager;
use crate::network::controller::{
    NetworkCommand, NetworkEvent, NetworkSnapshot, PeerSnapshot, Reachability,
};
use crate::network::limits::{
    DENIED_CONNECTION_TTL, INVALID_SIGNATURE_BLOCK, MALFORMED_BLOCK, MAX_BLOCKED_PEERS,
    MAX_DENIED_CONNECTIONS, MAX_IDENTIFY_ADDRESSES, MINOR_BLOCK, TARGET_CONNECTED_PEERS,
};
use crate::network::metrics::{NetworkMetrics, ProcessSampler};
use crate::network::rate_limit::RateLimiter;
use crate::network::replay::{ReplayDecision, ReplayState};
use crate::protocol::record::{unix_time_ms, FlaggedFileRecord, RecordValidation, RecordValidator};
use crate::protocol::sync::{
    InventorySummary, SyncErrorCode, SyncRequest, SyncResponse, MAX_IDS_PER_RESPONSE,
    MAX_PENDING_SYNC_REQUESTS_PER_PEER, MAX_REQUESTED_RECORDS, MAX_SIMULTANEOUS_SYNC_PEERS,
};
use crate::protocol::version::GOSSIP_TOPIC;
use crate::storage::{
    PersistError, PersistEvent, PersistRequest, PersistenceHandle, SharedSignatureDb,
};
use futures::StreamExt;
use libp2p::{
    autonat, gossipsub, identify, kad, mdns,
    multiaddr::Protocol,
    ping, relay, request_response,
    swarm::{Swarm, SwarmEvent},
    Multiaddr, PeerId, SwarmBuilder,
};
use lru::LruCache;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::num::{NonZeroU8, NonZeroUsize};
use std::sync::{atomic::Ordering, Arc};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

enum RunOutcome {
    Reset,
    Shutdown,
}

pub async fn run_engine(
    config: NetworkConfig,
    identity_store: IdentityStore,
    mut identity: StoredIdentity,
    database: SharedSignatureDb,
    mut command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
    snapshot: Arc<RwLock<NetworkSnapshot>>,
) -> anyhow::Result<()> {
    let (persistence, mut persistence_rx) = PersistenceHandle::spawn(database.clone());
    loop {
        let outcome = run_swarm(
            &config,
            identity.clone(),
            database.clone(),
            &mut command_rx,
            &event_tx,
            &snapshot,
            persistence.clone(),
            &mut persistence_rx,
        )
        .await?;
        match outcome {
            RunOutcome::Shutdown => return Ok(()),
            RunOutcome::Reset => {
                database.clear_identity_state()?;
                identity = identity_store.reset()?;
                snapshot.write().local_peer_id = Some(identity.peer_id);
                try_event(
                    &event_tx,
                    NetworkEvent::IdentityReset {
                        peer_id: identity.peer_id,
                    },
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_swarm(
    config: &NetworkConfig,
    identity: StoredIdentity,
    database: SharedSignatureDb,
    command_rx: &mut mpsc::Receiver<NetworkCommand>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    snapshot: &Arc<RwLock<NetworkSnapshot>>,
    persistence: PersistenceHandle,
    persistence_rx: &mut mpsc::Receiver<PersistEvent>,
) -> anyhow::Result<RunOutcome> {
    let mut swarm = build_swarm(config, &identity)?;
    for address in &config.listen_addresses {
        swarm.listen_on(address.clone())?;
    }
    configure_bootstrap(&mut swarm, &config.bootstrap_peers);
    configure_relays(&mut swarm, &config.relay_addresses)?;
    let _ = swarm.behaviour_mut().kad.bootstrap();

    let (sign_tx, mut sign_rx, signer_task) = spawn_signer(database.clone(), identity.clone());
    let (db_action_tx, mut db_action_rx) = mpsc::channel(64);
    let database_records = database.count();
    let database_size_bytes = database.database_size_bytes();
    let storage_safety = database.storage_safety_status().ok();
    let mut replay = ReplayState::default();
    replay.load_persistent_state(
        database.origin_highest_sequences().unwrap_or_default(),
        database
            .active_record_ids(unix_time_ms())
            .unwrap_or_default(),
    );
    let replay_now = Instant::now();
    for (record_id, origin, sequence) in database
        .recent_replay_seeds(
            crate::network::limits::RECENT_RECORD_CAPACITY,
            unix_time_ms(),
        )
        .unwrap_or_default()
    {
        replay.accept(record_id, origin, sequence, replay_now);
    }
    let mut actor = Actor {
        swarm,
        identity,
        database,
        persistence,
        event_tx,
        snapshot,
        replay,
        rate_limiter: RateLimiter::default(),
        connections: ConnectionManager::default(),
        metrics: NetworkMetrics::default(),
        blocked: LruCache::new(NonZeroUsize::new(MAX_BLOCKED_PEERS).expect("non-zero")),
        pending_sync: HashMap::new(),
        sync_sessions: HashMap::new(),
        listen_addresses: Vec::new(),
        reachability: Reachability::Unknown,
        dht_status: "bootstrapping".to_owned(),
        validator: RecordValidator::default(),
        db_action_tx,
        global_records: WindowCounter::new(
            crate::network::limits::GLOBAL_RECORDS_PER_MINUTE,
            Duration::from_secs(60),
        ),
        database_records,
        database_size_bytes,
        process_sampler: ProcessSampler::default(),
        connection_attempts: LruCache::new(
            NonZeroUsize::new(10_000).expect("non-zero connection-source limit"),
        ),
        denied_connections: DeniedConnections::new(),
        external_candidates: LruCache::new(
            NonZeroUsize::new(1_024).expect("non-zero external candidates"),
        ),
        promoted_external: HashMap::new(),
        storage_safety_mode: storage_safety.as_ref().is_some_and(|status| !status.safe),
        storage_safety_reason: storage_safety.and_then(|status| status.reason),
        allow_private_test_network: config.allow_private_test_network,
        sync_records_response_delay: config.sync_records_response_delay,
    };
    try_event(
        event_tx,
        NetworkEvent::Started {
            peer_id: actor.identity.peer_id,
        },
    );
    let mut snapshot_tick = tokio::time::interval(Duration::from_secs(1));
    let mut sync_tick = tokio::time::interval(config.sync_interval);
    let mut cleanup_tick = tokio::time::interval(Duration::from_secs(60 * 60));
    loop {
        tokio::select! {
            event = actor.swarm.select_next_some() => actor.handle_swarm_event(event),
            command = command_rx.recv() => {
                match command {
                    Some(NetworkCommand::ResetIdentity) => {
                        signer_task.abort();
                        let peers: Vec<_> = actor.connections.snapshots().into_iter().map(|p| p.peer_id).collect();
                        for peer in peers {
                            let _ = actor.swarm.disconnect_peer_id(peer);
                        }
                        return Ok(RunOutcome::Reset);
                    }
                    Some(NetworkCommand::Shutdown) | None => {
                        signer_task.abort();
                        return Ok(RunOutcome::Shutdown);
                    }
                    Some(command) => actor.handle_command(command, &sign_tx),
                }
            }
            Some(result) = sign_rx.recv() => actor.handle_signed_record(result),
            Some(event) = persistence_rx.recv() => actor.handle_persisted(event),
            Some(action) = db_action_rx.recv() => actor.handle_db_action(action),
            _ = snapshot_tick.tick() => actor.update_snapshot(),
            _ = sync_tick.tick() => actor.start_best_sync_peer(),
            _ = cleanup_tick.tick() => actor.schedule_cleanup(),
        }
    }
}

fn build_swarm(
    config: &NetworkConfig,
    identity: &StoredIdentity,
) -> anyhow::Result<Swarm<ProtonetBehaviour>> {
    let mdns = config.enable_mdns;
    let relay_server = config.enable_relay_server;
    let peer_scoring = !config.allow_private_test_network;
    let swarm = SwarmBuilder::with_existing_identity(identity.keypair.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_relay_client(libp2p::noise::Config::new, libp2p::yamux::Config::default)?
        .with_behaviour(move |key, relay| {
            ProtonetBehaviour::new(key, relay, mdns, relay_server, peer_scoring)
                .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })
        })?
        .with_swarm_config(|config| {
            config
                .with_idle_connection_timeout(crate::network::limits::IDLE_TIMEOUT)
                .with_dial_concurrency_factor(NonZeroU8::new(8).expect("non-zero dial concurrency"))
        })
        .build();
    Ok(swarm)
}

fn configure_bootstrap(swarm: &mut Swarm<ProtonetBehaviour>, addresses: &[Multiaddr]) {
    let mut preferred = addresses.to_vec();
    prefer_quic(&mut preferred);
    for address in preferred {
        if let Some(peer) = peer_from_address(&address) {
            let transport = without_trailing_peer(&address);
            swarm
                .behaviour_mut()
                .kad
                .add_address(&peer, transport.clone());
            swarm.add_peer_address(peer, transport.clone());
            let _ = swarm.dial(address);
        }
    }
}

fn configure_relays(
    swarm: &mut Swarm<ProtonetBehaviour>,
    addresses: &[Multiaddr],
) -> anyhow::Result<()> {
    for address in addresses.iter().take(16) {
        let mut circuit = address.clone();
        circuit.push(Protocol::P2pCircuit);
        swarm.listen_on(circuit)?;
    }
    Ok(())
}

struct Actor<'a> {
    swarm: Swarm<ProtonetBehaviour>,
    identity: StoredIdentity,
    database: SharedSignatureDb,
    persistence: PersistenceHandle,
    event_tx: &'a mpsc::Sender<NetworkEvent>,
    snapshot: &'a Arc<RwLock<NetworkSnapshot>>,
    replay: ReplayState,
    rate_limiter: RateLimiter,
    connections: ConnectionManager,
    metrics: NetworkMetrics,
    blocked: LruCache<PeerId, Instant>,
    pending_sync: HashMap<request_response::OutboundRequestId, PendingSync>,
    sync_sessions: HashMap<PeerId, SyncSession>,
    listen_addresses: Vec<Multiaddr>,
    reachability: Reachability,
    dht_status: String,
    validator: RecordValidator,
    db_action_tx: mpsc::Sender<DbAction>,
    global_records: WindowCounter,
    database_records: usize,
    database_size_bytes: u64,
    process_sampler: ProcessSampler,
    connection_attempts: LruCache<String, WindowCounter>,
    denied_connections: DeniedConnections,
    external_candidates: LruCache<Multiaddr, ExternalCandidate>,
    promoted_external: HashMap<Multiaddr, Instant>,
    storage_safety_mode: bool,
    storage_safety_reason: Option<String>,
    allow_private_test_network: bool,
    sync_records_response_delay: Duration,
}

#[derive(Debug)]
enum PendingSync {
    Inventory { peer: PeerId },
    Ids { peer: PeerId, bucket: i64 },
    Records { peer: PeerId },
}

#[derive(Debug)]
struct SyncSession {
    started: Instant,
    differing_buckets: VecDeque<i64>,
    outstanding: HashSet<request_response::OutboundRequestId>,
    received: u64,
}

enum DbAction {
    SendResponse {
        peer: PeerId,
        channel: request_response::ResponseChannel<SyncResponse>,
        response: SyncResponse,
    },
    InventoryCompared {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        differing_buckets: Vec<i64>,
    },
    IdsCompared {
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        bucket: i64,
        missing: Vec<[u8; 32]>,
        next_cursor: Option<[u8; 32]>,
    },
    Maintenance {
        records: usize,
        database_size_bytes: u64,
        storage_safe: bool,
        storage_reason: Option<String>,
    },
}

struct ExternalCandidate {
    contributors: HashSet<PeerId>,
    updated: Instant,
}

struct DeniedConnections {
    values: LruCache<libp2p::swarm::ConnectionId, Instant>,
}

impl DeniedConnections {
    fn new() -> Self {
        Self {
            values: LruCache::new(
                NonZeroUsize::new(MAX_DENIED_CONNECTIONS)
                    .expect("non-zero denied connection limit"),
            ),
        }
    }

    fn insert(&mut self, id: libp2p::swarm::ConnectionId, now: Instant) {
        self.purge(now);
        self.values.put(id, now + DENIED_CONNECTION_TTL);
    }

    fn remove(&mut self, id: &libp2p::swarm::ConnectionId) -> bool {
        self.values.pop(id).is_some()
    }

    fn purge(&mut self, now: Instant) {
        while self
            .values
            .peek_lru()
            .is_some_and(|(_, expires)| *expires <= now)
        {
            self.values.pop_lru();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.values.len()
    }
}

impl Actor<'_> {
    fn handle_command(&mut self, command: NetworkCommand, sign_tx: &mpsc::Sender<SignRequest>) {
        match command {
            NetworkCommand::PublishFile {
                sha256,
                blake3,
                file_size,
                file_name,
            } => {
                if self.storage_safety_mode {
                    self.violation(None, "storage safety mode blocks new records");
                    return;
                }
                if sign_tx
                    .try_send(SignRequest {
                        sha256,
                        blake3,
                        file_size,
                        file_name,
                    })
                    .is_err()
                {
                    self.violation(None, "local signing queue is full");
                }
            }
            NetworkCommand::Connect(address) => {
                if address.to_vec().len() <= MAX_ADDRESS_BYTES {
                    if let Err(error) = self.swarm.dial(address) {
                        self.violation(None, &format!("dial rejected: {error}"));
                    }
                } else {
                    self.violation(None, "multiaddress exceeds the configured bound");
                }
            }
            NetworkCommand::Disconnect(peer) => {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
            NetworkCommand::AddBootstrapPeer(peer, address) => {
                if address.to_vec().len() <= MAX_ADDRESS_BYTES {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer, address.clone());
                    self.swarm.add_peer_address(peer, address);
                    let _ = self.swarm.behaviour_mut().kad.bootstrap();
                }
            }
            NetworkCommand::RemoveBootstrapPeer(peer) => {
                self.swarm.behaviour_mut().kad.remove_peer(&peer);
            }
            NetworkCommand::RequestSync(peer) => self.start_sync(peer),
            NetworkCommand::RequestSyncAny => self.start_best_sync_peer(),
            NetworkCommand::ResetIdentity | NetworkCommand::Shutdown => {}
        }
    }

    fn handle_signed_record(&mut self, result: anyhow::Result<FlaggedFileRecord>) {
        if self.storage_safety_mode {
            self.violation(None, "storage safety mode blocks new records");
            return;
        }
        match result {
            Ok(record) => {
                if !self.persistence.try_enqueue(PersistRequest {
                    record,
                    source: None,
                    received_at: Instant::now(),
                    gossip_validation: None,
                }) {
                    self.metrics
                        .queue_saturations
                        .fetch_add(1, Ordering::Relaxed);
                    self.violation(None, "persistence queue saturated");
                }
            }
            Err(error) => self.violation(None, &format!("record signing failed: {error:#}")),
        }
    }

    fn handle_persisted(&mut self, event: PersistEvent) {
        let (
            record,
            source,
            received_at,
            persistence_micros,
            database_size_bytes,
            gossip_validation,
        ) = match event {
            PersistEvent::Stored {
                record,
                source,
                received_at,
                persistence_micros,
                database_size_bytes,
                gossip_validation,
            } => (
                *record,
                source,
                received_at,
                persistence_micros,
                database_size_bytes,
                gossip_validation,
            ),
            PersistEvent::Duplicate {
                record_id,
                origin,
                sequence,
                persistence_micros,
                database_size_bytes,
                gossip_validation,
            } => {
                if let Some(origin) = origin {
                    self.replay
                        .accept(record_id, origin, sequence, Instant::now());
                } else {
                    self.replay.forget(&record_id);
                }
                self.metrics.record_persistence(persistence_micros);
                self.database_size_bytes = database_size_bytes;
                self.metrics
                    .duplicates_ignored
                    .fetch_add(1, Ordering::Relaxed);
                if let Some((message_id, source)) = gossip_validation {
                    self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Ignore);
                }
                return;
            }
            PersistEvent::Failed {
                record_id,
                error,
                persistence_micros,
                database_size_bytes,
                gossip_validation,
            } => {
                self.replay.forget(&record_id);
                self.metrics.record_persistence(persistence_micros);
                self.database_size_bytes = database_size_bytes;
                let reason = match error {
                    PersistError::StorageSafety(reason) => reason,
                    PersistError::Database(reason) => {
                        format!("database persistence failed: {reason}")
                    }
                };
                self.storage_safety_mode = true;
                self.storage_safety_reason = Some(reason.clone());
                try_event(
                    self.event_tx,
                    NetworkEvent::StorageSafetyChanged {
                        active: true,
                        reason: Some(reason.clone()),
                    },
                );
                self.violation(
                    None,
                    &format!(
                        "record {} was not persisted: {reason}",
                        crate::signature::hasher::hex(&record_id)
                    ),
                );
                if let Some((message_id, source)) = gossip_validation {
                    self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Ignore);
                }
                return;
            }
        };
        if let Ok(origin) = record.origin_peer_id() {
            self.replay
                .accept(record.record_id, origin, record.sequence, Instant::now());
        }
        if let Some((message_id, source)) = gossip_validation {
            self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Accept);
        }
        self.metrics.record_persistence(persistence_micros);
        self.database_records = self.database_records.saturating_add(1);
        self.database_size_bytes = database_size_bytes;
        let elapsed = received_at.elapsed().as_micros().min(u64::MAX as u128) as u64;
        self.metrics.record_propagation(elapsed);
        if let Some(source) = source {
            self.metrics
                .records_received
                .fetch_add(1, Ordering::Relaxed);
            self.connections
                .note_record(&source, record.encode().map(|v| v.len()).unwrap_or(0));
            try_event(
                self.event_tx,
                NetworkEvent::RecordReceived {
                    record_id: record.record_id,
                    from: source,
                    file_name: record.file_name,
                },
            );
            if let Some(session) = self.sync_sessions.get_mut(&source) {
                session.received = session.received.saturating_add(1);
                try_event(
                    self.event_tx,
                    NetworkEvent::SyncProgress {
                        peer_id: source,
                        received: session.received,
                    },
                );
            }
        } else {
            if record.origin_peer_id().ok() != Some(self.identity.peer_id) {
                return;
            }
            match record.encode() {
                Ok(encoded) => match self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(gossipsub::IdentTopic::new(GOSSIP_TOPIC), encoded.clone())
                {
                    Ok(_) => {
                        self.metrics.records_sent.fetch_add(1, Ordering::Relaxed);
                        self.metrics
                            .bytes_sent
                            .fetch_add(encoded.len() as u64, Ordering::Relaxed);
                        try_event(
                            self.event_tx,
                            NetworkEvent::RecordPublished {
                                record_id: record.record_id,
                                file_name: record.file_name,
                            },
                        );
                    }
                    Err(error) => {
                        self.violation(None, &format!("gossip publication failed: {error}"))
                    }
                },
                Err(error) => self.violation(None, &format!("record encoding failed: {error}")),
            }
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(event) => self.handle_behaviour(event),
            SwarmEvent::ConnectionEstablished {
                peer_id,
                endpoint,
                connection_id,
                num_established,
                ..
            } => {
                if self.denied_connections.remove(&connection_id) {
                    self.swarm.close_connection(connection_id);
                    self.violation(None, "connection-attempt rate exceeded for source IP");
                    return;
                }
                if self.is_blocked(&peer_id) {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }
                if !self.connections.can_accept(&endpoint) {
                    self.swarm.close_connection(connection_id);
                    self.violation(
                        Some(peer_id),
                        "connection diversity limit reached for source prefix",
                    );
                    return;
                }
                if num_established.get() > 1 {
                    let prefer_outbound = self.identity.peer_id.to_bytes() < peer_id.to_bytes();
                    let current_outbound =
                        matches!(endpoint, libp2p::core::ConnectedPoint::Dialer { .. });
                    if prefer_outbound != current_outbound {
                        self.swarm.close_connection(connection_id);
                        return;
                    }
                }
                self.connections
                    .connected(peer_id, &endpoint, Instant::now());
                let state = self
                    .connections
                    .snapshots()
                    .into_iter()
                    .find(|state| state.peer_id == peer_id);
                if let Some(state) = state {
                    try_event(
                        self.event_tx,
                        NetworkEvent::PeerConnected {
                            peer_id,
                            address: state.address,
                            directness: state.directness,
                            transport: state.transport,
                        },
                    );
                }
                if self.sync_sessions.len() < MAX_SIMULTANEOUS_SYNC_PEERS {
                    self.start_sync(peer_id);
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                ..
            } => {
                self.denied_connections.remove(&connection_id);
                if self.connections.disconnected(&peer_id) {
                    self.sync_sessions.remove(&peer_id);
                    self.pending_sync.retain(|_, pending| match pending {
                        PendingSync::Inventory { peer }
                        | PendingSync::Ids { peer, .. }
                        | PendingSync::Records { peer } => peer != &peer_id,
                    });
                    try_event(self.event_tx, NetworkEvent::PeerDisconnected { peer_id });
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                if !self.listen_addresses.contains(&address) {
                    self.listen_addresses.push(address.clone());
                    try_event(
                        self.event_tx,
                        NetworkEvent::Listening {
                            address: address.clone(),
                        },
                    );
                }
                if self.allow_private_test_network {
                    self.swarm.add_external_address(address);
                }
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                self.listen_addresses.retain(|item| item != &address);
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                if address
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
                    && !self.listen_addresses.contains(&address)
                {
                    self.listen_addresses.push(address.clone());
                    try_event(self.event_tx, NetworkEvent::Listening { address });
                }
            }
            SwarmEvent::ExternalAddrExpired { address } => {
                self.listen_addresses.retain(|item| item != &address);
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                try_event(
                    self.event_tx,
                    NetworkEvent::LogMessage(format!(
                        "dial failed{}: {error}",
                        peer_id.map(|p| format!(" for {p}")).unwrap_or_default()
                    )),
                );
            }
            SwarmEvent::IncomingConnectionError {
                connection_id,
                error,
                ..
            } => {
                self.denied_connections.remove(&connection_id);
                self.violation(None, &format!("inbound connection rejected: {error}"));
            }
            SwarmEvent::IncomingConnection {
                connection_id,
                send_back_addr,
                ..
            } => {
                let key = source_address_key(&send_back_addr);
                let now = Instant::now();
                let allowed = self
                    .connection_attempts
                    .get_or_insert_mut(key, || WindowCounter::new(10, Duration::from_secs(60)))
                    .take(now);
                if !allowed {
                    self.denied_connections.insert(connection_id, now);
                    self.swarm.close_connection(connection_id);
                }
            }
            SwarmEvent::ListenerError { error, .. } => {
                self.violation(None, &format!("listener failed: {error}"));
            }
            _ => {}
        }
    }

    fn handle_behaviour(&mut self, event: BehaviourEvent) {
        match event {
            BehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => self.validate_gossip(propagation_source, message_id, message.data),
            BehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer, address) in peers.into_iter().take(32) {
                    if peer == self.identity.peer_id || address.to_vec().len() > MAX_ADDRESS_BYTES {
                        continue;
                    }
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer, address.clone());
                    self.swarm.add_peer_address(peer, address.clone());
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .add_explicit_peer(&peer);
                    if self.connections.len() < TARGET_CONNECTED_PEERS {
                        let mut dial = address;
                        dial.push(Protocol::P2p(peer));
                        let _ = self.swarm.dial(dial);
                    }
                }
            }
            BehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer, _) in peers {
                    self.swarm
                        .behaviour_mut()
                        .gossipsub
                        .remove_explicit_peer(&peer);
                }
            }
            BehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                if !info.protocol_version.starts_with("/protonet/1.") {
                    self.block(peer_id, MALFORMED_BLOCK);
                    self.violation(Some(peer_id), "unsupported major protocol version");
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    return;
                }
                self.connections
                    .set_protocol(&peer_id, info.protocol_version.clone());
                let learned_over_private = self
                    .connections
                    .snapshots()
                    .into_iter()
                    .find(|state| state.peer_id == peer_id)
                    .is_some_and(|state| address_is_private(&state.address));
                for address in info
                    .listen_addrs
                    .into_iter()
                    .filter(|address| {
                        valid_announced_address(address)
                            && (!address_is_private(address) || learned_over_private)
                    })
                    .take(MAX_IDENTIFY_ADDRESSES)
                {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, address.clone());
                    self.swarm.add_peer_address(peer_id, address);
                }
                if self.allow_private_test_network && address_is_private(&info.observed_addr) {
                    self.swarm.add_external_address(info.observed_addr);
                } else {
                    self.observe_external_address(peer_id, info.observed_addr);
                }
            }
            BehaviourEvent::Ping(ping::Event { peer, result, .. }) => {
                if let Ok(rtt) = result {
                    self.connections.set_rtt(&peer, rtt);
                }
            }
            BehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. }) => {
                self.reachability = match new {
                    autonat::NatStatus::Public(address) => {
                        if public_external_address(&address) {
                            self.swarm.add_external_address(address.clone());
                            self.promoted_external.insert(address, Instant::now());
                        }
                        Reachability::Public
                    }
                    autonat::NatStatus::Private => {
                        self.clear_promoted_external();
                        Reachability::Private
                    }
                    autonat::NatStatus::Unknown => Reachability::Unknown,
                };
                try_event(
                    self.event_tx,
                    NetworkEvent::ReachabilityChanged {
                        state: self.reachability,
                    },
                );
            }
            BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. }) => {
                self.dht_status = match result {
                    kad::QueryResult::Bootstrap(Ok(_)) => "ready".to_owned(),
                    kad::QueryResult::Bootstrap(Err(_)) => {
                        "degraded (peer links remain usable)".to_owned()
                    }
                    _ => self.dht_status.clone(),
                };
            }
            BehaviourEvent::Sync(event) => self.handle_sync_event(event),
            BehaviourEvent::Dcutr(event) => {
                try_event(
                    self.event_tx,
                    NetworkEvent::LogMessage(format!("direct-connection upgrade: {event:?}")),
                );
            }
            BehaviourEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
                relay_peer_id,
                ..
            }) => try_event(
                self.event_tx,
                NetworkEvent::RelayReservation { relay_peer_id },
            ),
            BehaviourEvent::RelayClient(event) => try_event(
                self.event_tx,
                NetworkEvent::LogMessage(format!("relay client: {event:?}")),
            ),
            BehaviourEvent::RelayServer(event) => {
                try_event(
                    self.event_tx,
                    NetworkEvent::LogMessage(format!("relay server: {event:?}")),
                );
            }
            BehaviourEvent::Identify(_)
            | BehaviourEvent::Autonat(_)
            | BehaviourEvent::Kad(_)
            | BehaviourEvent::ConnectionLimits(_)
            | BehaviourEvent::Gossipsub(_) => {}
        }
    }

    fn validate_gossip(&mut self, source: PeerId, message_id: gossipsub::MessageId, data: Vec<u8>) {
        let started = Instant::now();
        let now = Instant::now();
        self.metrics
            .bytes_received
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        if self.storage_safety_mode
            || self.is_blocked(&source)
            || !self.rate_limiter.allow_gossip(source, data.len(), now)
            || !self.global_records.take(now)
        {
            self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Reject);
            self.block(source, MINOR_BLOCK);
            let _ = self.swarm.disconnect_peer_id(source);
            return;
        }
        let validation = self.validator.validate_bytes(&data, unix_time_ms());
        let record = match validation {
            Ok(record) => record,
            Err(error) => {
                self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Reject);
                self.metrics
                    .invalid_rejected
                    .fetch_add(1, Ordering::Relaxed);
                let duration = if error == RecordValidation::InvalidSignature {
                    INVALID_SIGNATURE_BLOCK
                } else {
                    MALFORMED_BLOCK
                };
                if !self.rate_limiter.note_invalid(source, now)
                    || error == RecordValidation::InvalidSignature
                {
                    self.block(source, duration);
                    let _ = self.swarm.disconnect_peer_id(source);
                }
                self.violation(Some(source), &error.to_string());
                return;
            }
        };
        let origin = match record.origin_peer_id() {
            Ok(origin) => origin,
            Err(error) => {
                self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Reject);
                self.violation(Some(source), &error.to_string());
                return;
            }
        };
        match self
            .replay
            .check(&record.record_id, &origin, record.sequence, now)
        {
            ReplayDecision::Duplicate => {
                self.metrics
                    .duplicates_ignored
                    .fetch_add(1, Ordering::Relaxed);
                self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Ignore);
            }
            ReplayDecision::TooOld => {
                self.metrics
                    .invalid_rejected
                    .fetch_add(1, Ordering::Relaxed);
                self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Reject);
                self.violation(Some(source), "record sequence is outside the replay window");
            }
            ReplayDecision::New => {
                if !self.allow_ingestion_source(source, now) {
                    self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Reject);
                    self.block(source, MINOR_BLOCK);
                    return;
                }
                if self.persistence.try_enqueue(PersistRequest {
                    record: record.clone(),
                    source: Some(source),
                    received_at: Instant::now(),
                    gossip_validation: Some((message_id.clone(), source)),
                }) {
                    self.replay.mark_pending(record.record_id, now);
                } else {
                    self.metrics
                        .queue_saturations
                        .fetch_add(1, Ordering::Relaxed);
                    self.report_gossip(&message_id, &source, gossipsub::MessageAcceptance::Ignore);
                }
            }
        }
        self.metrics
            .record_validation(started.elapsed().as_micros().min(u64::MAX as u128) as u64);
    }

    fn report_gossip(
        &mut self,
        message_id: &gossipsub::MessageId,
        source: &PeerId,
        acceptance: gossipsub::MessageAcceptance,
    ) {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .report_message_validation_result(message_id, source, acceptance);
    }

    fn handle_sync_event(&mut self, event: request_response::Event<SyncRequest, SyncResponse>) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => self.prepare_sync_response(peer, request, channel),
                request_response::Message::Response {
                    request_id,
                    response,
                } => self.handle_sync_response(peer, request_id, response),
            },
            request_response::Event::OutboundFailure {
                peer, request_id, ..
            } => {
                self.pending_sync.remove(&request_id);
                if let Some(session) = self.sync_sessions.get_mut(&peer) {
                    session.outstanding.remove(&request_id);
                }
                self.pump_sync(peer);
            }
            request_response::Event::InboundFailure { peer, .. } => {
                self.violation(Some(peer), "malformed or stalled synchronization request");
            }
            request_response::Event::ResponseSent { .. } => {}
        }
    }

    fn prepare_sync_response(
        &mut self,
        peer: PeerId,
        request: SyncRequest,
        channel: request_response::ResponseChannel<SyncResponse>,
    ) {
        if !self.rate_limiter.allow_sync_request(peer, Instant::now())
            || request.validate().is_err()
        {
            let _ = self.swarm.behaviour_mut().sync.send_response(
                channel,
                SyncResponse::Error {
                    code: SyncErrorCode::TooLarge,
                },
            );
            return;
        }
        let database = self.database.clone();
        let tx = self.db_action_tx.clone();
        let response_delay = matches!(&request, SyncRequest::GetRecords { .. })
            .then_some(self.sync_records_response_delay)
            .unwrap_or(Duration::ZERO);
        tokio::task::spawn_blocking(move || {
            let response = match request {
                SyncRequest::GetInventory => database
                    .inventory(unix_time_ms())
                    .map(SyncResponse::Inventory),
                SyncRequest::GetRecordIds {
                    bucket_start,
                    cursor,
                    limit,
                } => database
                    .record_ids(
                        bucket_start,
                        cursor,
                        usize::from(limit).min(MAX_IDS_PER_RESPONSE),
                        unix_time_ms(),
                    )
                    .map(|(ids, next_cursor)| SyncResponse::RecordIds { ids, next_cursor }),
                SyncRequest::GetRecords { ids } => database
                    .records_by_ids(&ids)
                    .map(|records| SyncResponse::Records { records }),
            }
            .unwrap_or(SyncResponse::Error {
                code: SyncErrorCode::Internal,
            });
            if !response_delay.is_zero() {
                std::thread::sleep(response_delay);
            }
            let _ = tx.blocking_send(DbAction::SendResponse {
                peer,
                channel,
                response,
            });
        });
    }

    fn handle_sync_response(
        &mut self,
        peer: PeerId,
        request_id: request_response::OutboundRequestId,
        response: SyncResponse,
    ) {
        if let Ok(bytes) = postcard::to_allocvec(&response) {
            self.metrics
                .bytes_received
                .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        }
        let Some(pending) = self.pending_sync.remove(&request_id) else {
            return;
        };
        if matches!(&pending, PendingSync::Ids { .. })
            && self.pending_sync.values().any(|candidate| {
                matches!(candidate, PendingSync::Records { peer: candidate_peer } if *candidate_peer == peer)
            })
        {
            self.metrics
                .sync_response_reorders
                .fetch_add(1, Ordering::Relaxed);
        }
        if response.validate_bounds().is_err() {
            if let Some(session) = self.sync_sessions.get_mut(&peer) {
                session.outstanding.remove(&request_id);
            }
            self.violation(Some(peer), "oversized synchronization response");
            self.block(peer, MALFORMED_BLOCK);
            let _ = self.swarm.disconnect_peer_id(peer);
            return;
        }
        match (pending, response) {
            (PendingSync::Inventory { peer }, SyncResponse::Inventory(remote)) => {
                let database = self.database.clone();
                let tx = self.db_action_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let local = database.inventory(unix_time_ms()).unwrap_or_default();
                    let buckets = differing_buckets(&local, &remote);
                    let _ = tx.blocking_send(DbAction::InventoryCompared {
                        peer,
                        request_id,
                        differing_buckets: buckets,
                    });
                });
            }
            (PendingSync::Ids { peer, bucket }, SyncResponse::RecordIds { ids, next_cursor }) => {
                let database = self.database.clone();
                let tx = self.db_action_tx.clone();
                tokio::task::spawn_blocking(move || {
                    let existing: HashSet<_> = database
                        .records_by_ids(&ids)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|record| record.record_id)
                        .collect();
                    let missing = ids
                        .into_iter()
                        .filter(|id| !existing.contains(id))
                        .take(MAX_REQUESTED_RECORDS)
                        .collect();
                    let _ = tx.blocking_send(DbAction::IdsCompared {
                        peer,
                        request_id,
                        bucket,
                        missing,
                        next_cursor,
                    });
                });
            }
            (PendingSync::Records { peer }, SyncResponse::Records { records }) => {
                if let Some(session) = self.sync_sessions.get_mut(&peer) {
                    session.outstanding.remove(&request_id);
                }
                self.accept_sync_records(peer, records);
                self.pump_sync(peer);
            }
            _ => {
                self.violation(Some(peer), "unexpected synchronization response");
                if let Some(session) = self.sync_sessions.get_mut(&peer) {
                    session.outstanding.remove(&request_id);
                }
                self.pump_sync(peer);
            }
        }
    }

    fn handle_db_action(&mut self, action: DbAction) {
        match action {
            DbAction::SendResponse {
                peer,
                channel,
                response,
            } => {
                let bytes = postcard::to_allocvec(&response)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                if self
                    .rate_limiter
                    .allow_sync_response(peer, bytes, Instant::now())
                {
                    self.metrics
                        .bytes_sent
                        .fetch_add(bytes as u64, Ordering::Relaxed);
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .sync
                        .send_response(channel, response);
                }
            }
            DbAction::InventoryCompared {
                peer,
                request_id,
                differing_buckets,
            } => {
                if let Some(session) = self.sync_sessions.get_mut(&peer) {
                    session.outstanding.remove(&request_id);
                    session.differing_buckets = differing_buckets.into();
                }
                self.pump_sync(peer);
            }
            DbAction::IdsCompared {
                peer,
                request_id,
                bucket,
                missing,
                next_cursor,
            } => {
                if let Some(session) = self.sync_sessions.get_mut(&peer) {
                    session.outstanding.remove(&request_id);
                }
                if !missing.is_empty() {
                    let id = self
                        .swarm
                        .behaviour_mut()
                        .sync
                        .send_request(&peer, SyncRequest::GetRecords { ids: missing });
                    self.pending_sync.insert(id, PendingSync::Records { peer });
                    if let Some(session) = self.sync_sessions.get_mut(&peer) {
                        session.outstanding.insert(id);
                    }
                }
                if let Some(cursor) = next_cursor {
                    let can_send = self.sync_sessions.get(&peer).is_some_and(|session| {
                        session.outstanding.len() < MAX_PENDING_SYNC_REQUESTS_PER_PEER
                    });
                    if can_send {
                        let id = self.swarm.behaviour_mut().sync.send_request(
                            &peer,
                            SyncRequest::GetRecordIds {
                                bucket_start: bucket,
                                cursor: Some(cursor),
                                limit: MAX_IDS_PER_RESPONSE as u16,
                            },
                        );
                        self.pending_sync
                            .insert(id, PendingSync::Ids { peer, bucket });
                        if let Some(session) = self.sync_sessions.get_mut(&peer) {
                            session.outstanding.insert(id);
                        }
                    } else if let Some(session) = self.sync_sessions.get_mut(&peer) {
                        session.differing_buckets.push_front(bucket);
                    }
                }
                self.pump_sync(peer);
            }
            DbAction::Maintenance {
                records,
                database_size_bytes,
                storage_safe,
                storage_reason,
            } => {
                self.database_records = records;
                self.database_size_bytes = database_size_bytes;
                let active = !storage_safe;
                if active != self.storage_safety_mode
                    || storage_reason != self.storage_safety_reason
                {
                    self.storage_safety_mode = active;
                    self.storage_safety_reason = storage_reason.clone();
                    try_event(
                        self.event_tx,
                        NetworkEvent::StorageSafetyChanged {
                            active,
                            reason: storage_reason,
                        },
                    );
                }
            }
        }
    }

    fn accept_sync_records(&mut self, peer: PeerId, records: Vec<FlaggedFileRecord>) {
        if self.storage_safety_mode {
            return;
        }
        for record in records.into_iter().take(MAX_REQUESTED_RECORDS) {
            let now = Instant::now();
            if self.validator.validate(&record, unix_time_ms()).is_err() {
                self.violation(
                    Some(peer),
                    "invalid signed record in synchronization response",
                );
                continue;
            }
            let Ok(origin) = record.origin_peer_id() else {
                continue;
            };
            if self
                .replay
                .check(&record.record_id, &origin, record.sequence, now)
                != ReplayDecision::New
            {
                self.metrics
                    .duplicates_ignored
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if !self.allow_ingestion_source(peer, now) {
                self.block(peer, MINOR_BLOCK);
                break;
            }
            if self.persistence.try_enqueue(PersistRequest {
                record: record.clone(),
                source: Some(peer),
                received_at: now,
                gossip_validation: None,
            }) {
                self.replay.mark_pending(record.record_id, now);
            } else {
                self.metrics
                    .queue_saturations
                    .fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    fn start_sync(&mut self, peer: PeerId) {
        if self.sync_sessions.contains_key(&peer)
            || self.sync_sessions.len() >= MAX_SIMULTANEOUS_SYNC_PEERS
        {
            return;
        }
        let request_id = self
            .swarm
            .behaviour_mut()
            .sync
            .send_request(&peer, SyncRequest::GetInventory);
        self.pending_sync
            .insert(request_id, PendingSync::Inventory { peer });
        let mut outstanding = HashSet::new();
        outstanding.insert(request_id);
        self.sync_sessions.insert(
            peer,
            SyncSession {
                started: Instant::now(),
                differing_buckets: VecDeque::new(),
                outstanding,
                received: 0,
            },
        );
        try_event(self.event_tx, NetworkEvent::SyncStarted { peer_id: peer });
    }

    fn allow_ingestion_source(&mut self, peer: PeerId, now: Instant) -> bool {
        self.connections
            .source_keys(&peer)
            .is_some_and(|(ip, prefix)| self.rate_limiter.allow_ingestion_source(ip, prefix, now))
    }

    fn start_best_sync_peer(&mut self) {
        if self.sync_sessions.len() >= MAX_SIMULTANEOUS_SYNC_PEERS {
            return;
        }
        let candidate = self
            .connections
            .snapshots()
            .into_iter()
            .filter(|state| !self.sync_sessions.contains_key(&state.peer_id))
            .min_by_key(|state| state.round_trip_time.unwrap_or(Duration::MAX))
            .map(|state| state.peer_id);
        if let Some(peer) = candidate {
            self.start_sync(peer);
        }
    }

    fn observe_external_address(&mut self, peer: PeerId, address: Multiaddr) {
        let now = Instant::now();
        if record_external_observation(&mut self.external_candidates, peer, address.clone(), now) {
            self.swarm.add_external_address(address.clone());
            self.promoted_external.insert(address, now);
        }
    }

    fn expire_external_addresses(&mut self, now: Instant) {
        let ttl = Duration::from_secs(30 * 60);
        let stale_candidates: Vec<_> = self
            .external_candidates
            .iter()
            .filter(|(_, candidate)| now.saturating_duration_since(candidate.updated) > ttl)
            .map(|(address, _)| address.clone())
            .collect();
        for address in stale_candidates {
            self.external_candidates.pop(&address);
        }
        let stale_promoted: Vec<_> = self
            .promoted_external
            .iter()
            .filter(|(_, updated)| now.saturating_duration_since(**updated) > ttl)
            .map(|(address, _)| address.clone())
            .collect();
        for address in stale_promoted {
            self.promoted_external.remove(&address);
            self.swarm.remove_external_address(&address);
        }
    }

    fn clear_promoted_external(&mut self) {
        let addresses: Vec<_> = self.promoted_external.keys().cloned().collect();
        for address in addresses {
            self.swarm.remove_external_address(&address);
        }
        self.promoted_external.clear();
    }

    fn pump_sync(&mut self, peer: PeerId) {
        loop {
            let next = {
                let Some(session) = self.sync_sessions.get_mut(&peer) else {
                    return;
                };
                if session.outstanding.len() >= MAX_PENDING_SYNC_REQUESTS_PER_PEER {
                    return;
                }
                session.differing_buckets.pop_front()
            };
            let Some(bucket) = next else {
                let complete = self
                    .sync_sessions
                    .get(&peer)
                    .is_some_and(|session| session.outstanding.is_empty());
                if complete {
                    self.finish_sync(peer);
                }
                return;
            };
            let id = self.swarm.behaviour_mut().sync.send_request(
                &peer,
                SyncRequest::GetRecordIds {
                    bucket_start: bucket,
                    cursor: None,
                    limit: MAX_IDS_PER_RESPONSE as u16,
                },
            );
            self.pending_sync
                .insert(id, PendingSync::Ids { peer, bucket });
            if let Some(session) = self.sync_sessions.get_mut(&peer) {
                session.outstanding.insert(id);
            }
        }
    }

    fn finish_sync(&mut self, peer: PeerId) {
        if let Some(session) = self.sync_sessions.remove(&peer) {
            let _duration = session.started.elapsed();
            try_event(
                self.event_tx,
                NetworkEvent::SyncCompleted {
                    peer_id: peer,
                    received: session.received,
                },
            );
        }
    }

    fn block(&mut self, peer: PeerId, duration: Duration) {
        self.blocked.put(peer, Instant::now() + duration);
    }

    fn is_blocked(&mut self, peer: &PeerId) -> bool {
        let Some(until) = self.blocked.get(peer).copied() else {
            return false;
        };
        if until > Instant::now() {
            true
        } else {
            self.blocked.pop(peer);
            false
        }
    }

    fn violation(&self, peer: Option<PeerId>, reason: &str) {
        try_event(
            self.event_tx,
            NetworkEvent::ProtocolViolation {
                peer_id: peer,
                reason: reason.to_owned(),
            },
        );
    }

    fn update_snapshot(&mut self) {
        let now = Instant::now();
        self.denied_connections.purge(now);
        self.expire_external_addresses(now);
        for peer in self
            .connections
            .unverified_peers_older_than(crate::network::limits::HANDSHAKE_TIMEOUT, now)
        {
            self.violation(Some(peer), "Identify protocol handshake timed out");
            let _ = self.swarm.disconnect_peer_id(peer);
        }
        let timed_out: Vec<_> = self
            .sync_sessions
            .iter()
            .filter(|(_, session)| {
                session.started.elapsed()
                    > Duration::from_secs(crate::protocol::sync::MAX_SYNC_DURATION_SECS)
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in timed_out {
            self.pending_sync.retain(|_, pending| match pending {
                PendingSync::Inventory { peer: owner }
                | PendingSync::Ids { peer: owner, .. }
                | PendingSync::Records { peer: owner } => owner != &peer,
            });
            self.finish_sync(peer);
        }
        let topic = gossipsub::IdentTopic::new(GOSSIP_TOPIC);
        let peers = self
            .connections
            .snapshots()
            .into_iter()
            .map(|state| PeerSnapshot {
                peer_id: state.peer_id,
                address: state.address,
                directness: state.directness,
                transport: state.transport,
                round_trip_time: state.round_trip_time,
                protocol_version: state.protocol_version,
                records_received: state.records_received,
                bytes_sent: state.bytes_sent,
                bytes_received: state.bytes_received,
            })
            .collect();
        let mut snapshot = self.snapshot.write();
        snapshot.local_peer_id = Some(self.identity.peer_id);
        snapshot.peers = peers;
        snapshot.listen_addresses = self.listen_addresses.clone();
        snapshot.reachability = self.reachability;
        snapshot.dht_status = self.dht_status.clone();
        snapshot.gossipsub_mesh_size = self
            .swarm
            .behaviour()
            .gossipsub
            .mesh_peers(&topic.hash())
            .count();
        snapshot.persistence_queue_depth = self.persistence.depth();
        snapshot.replay_cache_size = self.replay.recent_len();
        snapshot.database_records = self.database_records;
        snapshot.database_size_bytes = self.database_size_bytes;
        snapshot.storage_safety_mode = self.storage_safety_mode;
        snapshot.storage_safety_reason = self.storage_safety_reason.clone();
        snapshot.metrics = self.metrics.snapshot();
        let (cpu, memory) = self.process_sampler.sample();
        snapshot.metrics.process_cpu_percent = cpu;
        snapshot.metrics.process_memory_bytes = memory;
        snapshot.metrics.queue_saturations = snapshot
            .metrics
            .queue_saturations
            .saturating_add(self.persistence.saturations());
    }

    fn schedule_cleanup(&self) {
        let database = self.database.clone();
        let tx = self.db_action_tx.clone();
        tokio::task::spawn_blocking(move || {
            let _ = database.cleanup_expired(unix_time_ms());
            let safety = database.storage_safety_status().ok();
            let _ = tx.blocking_send(DbAction::Maintenance {
                records: database.count(),
                database_size_bytes: database.database_size_bytes(),
                storage_safe: safety.as_ref().is_some_and(|status| status.safe),
                storage_reason: safety.and_then(|status| status.reason),
            });
        });
    }
}

fn spawn_signer(
    database: SharedSignatureDb,
    identity: StoredIdentity,
) -> (
    mpsc::Sender<SignRequest>,
    mpsc::Receiver<anyhow::Result<FlaggedFileRecord>>,
    tokio::task::JoinHandle<()>,
) {
    let (tx, mut rx) = mpsc::channel::<SignRequest>(256);
    let (result_tx, result_rx) = mpsc::channel(256);
    let task = tokio::spawn(async move {
        while let Some(request) = rx.recv().await {
            let database = database.clone();
            let identity = identity.clone();
            let result = tokio::task::spawn_blocking(move || {
                let sequence = database.next_local_sequence(&identity.peer_id)?;
                FlaggedFileRecord::create(
                    &identity.keypair,
                    sequence,
                    unix_time_ms(),
                    request.sha256,
                    request.blake3,
                    request.file_size,
                    request.file_name,
                )
                .map_err(anyhow::Error::msg)
            })
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("signer task failed: {error}")));
            if result_tx.send(result).await.is_err() {
                break;
            }
        }
    });
    (tx, result_rx, task)
}

struct SignRequest {
    sha256: [u8; 32],
    blake3: [u8; 32],
    file_size: u64,
    file_name: Option<String>,
}

fn differing_buckets(local: &InventorySummary, remote: &InventorySummary) -> Vec<i64> {
    let local: HashMap<_, _> = local
        .bucket_digests
        .iter()
        .map(|bucket| (bucket.start_unix, (bucket.record_count, bucket.digest)))
        .collect();
    remote
        .bucket_digests
        .iter()
        .filter(|bucket| {
            local.get(&bucket.start_unix).copied() != Some((bucket.record_count, bucket.digest))
        })
        .map(|bucket| bucket.start_unix)
        .collect()
}

fn without_trailing_peer(address: &Multiaddr) -> Multiaddr {
    let mut result = address.clone();
    if matches!(result.iter().last(), Some(Protocol::P2p(_))) {
        result.pop();
    }
    result
}

fn valid_announced_address(address: &Multiaddr) -> bool {
    if address.to_vec().len() > MAX_ADDRESS_BYTES {
        return false;
    }
    !address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast(),
        Protocol::Ip6(ip) => ip.is_unspecified() || ip.is_multicast(),
        _ => false,
    })
}

fn public_external_address(address: &Multiaddr) -> bool {
    if !valid_announced_address(address) {
        return false;
    }
    let mut has_public_ip = false;
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(ip) => {
                let octets = ip.octets();
                let reserved = ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_multicast()
                    || ip.is_documentation()
                    || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                    || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                    || octets[0] >= 240;
                if reserved {
                    return false;
                }
                has_public_ip = true;
            }
            Protocol::Ip6(ip) => {
                let first = ip.segments()[0];
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80
                    || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0x0db8)
                {
                    return false;
                }
                has_public_ip = true;
            }
            Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                return false
            }
            _ => {}
        }
    }
    has_public_ip
}

fn record_external_observation(
    candidates: &mut LruCache<Multiaddr, ExternalCandidate>,
    peer: PeerId,
    address: Multiaddr,
    now: Instant,
) -> bool {
    if !public_external_address(&address) {
        return false;
    }
    let candidate = candidates.get_or_insert_mut(address, || ExternalCandidate {
        contributors: HashSet::new(),
        updated: now,
    });
    candidate.contributors.insert(peer);
    candidate.updated = now;
    candidate.contributors.len() >= 3
}

fn address_is_private(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        Protocol::Ip6(ip) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
        _ => false,
    })
}

fn source_address_key(address: &Multiaddr) -> String {
    address
        .iter()
        .find_map(|protocol| match protocol {
            Protocol::Ip4(ip) => Some(ip.to_string()),
            Protocol::Ip6(ip) => Some(ip.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| "non-ip".to_owned())
}

fn try_event(tx: &mpsc::Sender<NetworkEvent>, event: NetworkEvent) {
    let _ = tx.try_send(event);
}

struct WindowCounter {
    limit: u64,
    period: Duration,
    start: Instant,
    used: u64,
}

impl WindowCounter {
    fn new(limit: u64, period: Duration) -> Self {
        Self {
            limit,
            period,
            start: Instant::now(),
            used: 0,
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.start) >= self.period {
            self.start = now;
            self.used = 0;
        }
        if self.used >= self.limit {
            return false;
        }
        self.used += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventories_only_request_differing_buckets() {
        let local = InventorySummary {
            bucket_digests: vec![crate::protocol::BucketDigest {
                start_unix: 1,
                end_unix: 2,
                record_count: 1,
                digest: [1; 32],
            }],
            ..InventorySummary::default()
        };
        assert!(differing_buckets(&local, &local).is_empty());
        let mut remote = local.clone();
        remote.bucket_digests[0].digest = [2; 32];
        assert_eq!(differing_buckets(&local, &remote), vec![1]);
    }

    #[test]
    fn unsafe_announced_addresses_are_rejected() {
        assert!(!valid_announced_address(
            &"/ip4/0.0.0.0/tcp/1".parse().unwrap()
        ));
        assert!(valid_announced_address(
            &"/ip4/192.168.1.2/tcp/1".parse().unwrap()
        ));
        assert!(!public_external_address(
            &"/ip4/192.168.1.2/tcp/1".parse().unwrap()
        ));
        assert!(public_external_address(
            &"/ip4/8.8.8.8/udp/443/quic-v1".parse().unwrap()
        ));
        assert!(!public_external_address(
            &"/dns4/rebind.example/tcp/1".parse().unwrap()
        ));
    }

    #[test]
    fn rejected_handshake_tracking_stays_bounded_after_one_hundred_thousand_aborts() {
        let mut denied = DeniedConnections::new();
        let now = Instant::now();
        for id in 0..100_000 {
            let connection = libp2p::swarm::ConnectionId::new_unchecked(id);
            denied.insert(connection, now);
            if id % 2 == 0 {
                denied.remove(&connection);
            }
        }
        assert!(denied.len() <= MAX_DENIED_CONNECTIONS);
        denied.purge(now + DENIED_CONNECTION_TTL + Duration::from_secs(1));
        assert_eq!(denied.len(), 0);
    }

    #[test]
    fn external_address_requires_independent_matching_public_observers() {
        let mut candidates = LruCache::new(NonZeroUsize::new(8).expect("non-zero"));
        let address: Multiaddr = "/ip4/8.8.8.8/udp/4001/quic-v1".parse().unwrap();
        let first = PeerId::random();
        assert!(!record_external_observation(
            &mut candidates,
            first,
            address.clone(),
            Instant::now(),
        ));
        assert!(!record_external_observation(
            &mut candidates,
            first,
            address.clone(),
            Instant::now(),
        ));
        assert!(!record_external_observation(
            &mut candidates,
            PeerId::random(),
            address.clone(),
            Instant::now(),
        ));
        assert!(record_external_observation(
            &mut candidates,
            PeerId::random(),
            address,
            Instant::now(),
        ));
        assert!(!record_external_observation(
            &mut candidates,
            PeerId::random(),
            "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            Instant::now(),
        ));
    }
}
