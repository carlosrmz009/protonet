use crate::network::limits::{MAX_CONNECTIONS_PER_IP_PREFIX, MAX_RELAY_ONLY_CONNECTIONS};
use libp2p::{core::ConnectedPoint, Multiaddr, PeerId};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    TcpNoiseYamux,
    CircuitRelay,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Directness {
    Direct,
    Relayed,
}

#[derive(Debug, Clone)]
pub struct PeerConnectionState {
    pub peer_id: PeerId,
    pub connection_count: usize,
    pub direction: ConnectionDirection,
    pub transport: TransportKind,
    pub directness: Directness,
    pub address: Multiaddr,
    pub connected_at: Instant,
    pub last_activity: Instant,
    pub round_trip_time: Option<Duration>,
    pub protocol_version: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub records_received: u64,
}

#[derive(Default)]
pub struct ConnectionManager {
    peers: HashMap<PeerId, PeerConnectionState>,
}

impl ConnectionManager {
    pub fn can_accept(&self, endpoint: &ConnectedPoint) -> bool {
        let address = match endpoint {
            ConnectedPoint::Dialer { address, .. } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        };
        let (_, directness) = classify_address(address);
        if directness == Directness::Relayed
            && self
                .peers
                .values()
                .filter(|state| state.directness == Directness::Relayed)
                .count()
                >= MAX_RELAY_ONLY_CONNECTIONS
        {
            return false;
        }
        let Some(prefix) = address_prefix(address) else {
            return directness == Directness::Relayed;
        };
        self.peers
            .values()
            .filter(|state| address_prefix(&state.address).as_deref() == Some(prefix.as_str()))
            .count()
            < MAX_CONNECTIONS_PER_IP_PREFIX
    }

    pub fn connected(&mut self, peer: PeerId, endpoint: &ConnectedPoint, now: Instant) {
        let (direction, address) = match endpoint {
            ConnectedPoint::Dialer { address, .. } => {
                (ConnectionDirection::Outbound, address.clone())
            }
            ConnectedPoint::Listener { send_back_addr, .. } => {
                (ConnectionDirection::Inbound, send_back_addr.clone())
            }
        };
        let (transport, directness) = classify_address(&address);
        let state = self.peers.entry(peer).or_insert(PeerConnectionState {
            peer_id: peer,
            connection_count: 0,
            direction,
            transport,
            directness,
            address,
            connected_at: now,
            last_activity: now,
            round_trip_time: None,
            protocol_version: None,
            bytes_sent: 0,
            bytes_received: 0,
            records_received: 0,
        });
        state.connection_count = state.connection_count.saturating_add(1);
        state.last_activity = now;
    }

    pub fn disconnected(&mut self, peer: &PeerId) -> bool {
        let Some(state) = self.peers.get_mut(peer) else {
            return false;
        };
        state.connection_count = state.connection_count.saturating_sub(1);
        if state.connection_count == 0 {
            self.peers.remove(peer);
            return true;
        }
        false
    }

    pub fn set_rtt(&mut self, peer: &PeerId, rtt: Duration) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.round_trip_time = Some(rtt);
            state.last_activity = Instant::now();
        }
    }

    pub fn set_protocol(&mut self, peer: &PeerId, protocol: String) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.protocol_version = Some(protocol);
        }
    }

    pub fn note_record(&mut self, peer: &PeerId, bytes: usize) {
        if let Some(state) = self.peers.get_mut(peer) {
            state.records_received = state.records_received.saturating_add(1);
            state.bytes_received = state.bytes_received.saturating_add(bytes as u64);
            state.last_activity = Instant::now();
        }
    }

    pub fn snapshots(&self) -> Vec<PeerConnectionState> {
        self.peers.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn source_keys(&self, peer: &PeerId) -> Option<(String, String)> {
        let address = &self.peers.get(peer)?.address;
        Some((address_ip(address)?, address_prefix(address)?))
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn unverified_peers_older_than(&self, age: Duration, now: Instant) -> Vec<PeerId> {
        self.peers
            .values()
            .filter(|state| {
                state.protocol_version.is_none()
                    && now.saturating_duration_since(state.connected_at) > age
            })
            .map(|state| state.peer_id)
            .collect()
    }
}

fn address_ip(address: &Multiaddr) -> Option<String> {
    address.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => Some(ip.to_string()),
        libp2p::multiaddr::Protocol::Ip6(ip) => Some(ip.to_string()),
        _ => None,
    })
}

fn address_prefix(address: &Multiaddr) -> Option<String> {
    address.iter().find_map(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(ip) => {
            let octets = ip.octets();
            Some(format!("v4-{}.{}.{}", octets[0], octets[1], octets[2]))
        }
        libp2p::multiaddr::Protocol::Ip6(ip) => {
            let segments = ip.segments();
            Some(format!(
                "v6-{:x}:{:x}:{:x}:{:x}",
                segments[0], segments[1], segments[2], segments[3]
            ))
        }
        _ => None,
    })
}

pub fn classify_address(address: &Multiaddr) -> (TransportKind, Directness) {
    let text = address.to_string();
    let relayed = text.contains("/p2p-circuit");
    let transport = if relayed {
        TransportKind::CircuitRelay
    } else if text.contains("/quic-v1") {
        TransportKind::Quic
    } else if text.contains("/tcp/") {
        TransportKind::TcpNoiseYamux
    } else {
        TransportKind::Unknown
    };
    (
        transport,
        if relayed {
            Directness::Relayed
        } else {
            Directness::Direct
        },
    )
}
