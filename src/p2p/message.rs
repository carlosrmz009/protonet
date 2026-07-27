use crate::signature::FileSignature;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum P2pMessage {
    /// Initial Handshake when two nodes establish a TCP connection
    Handshake {
        node_id: String,
        listen_port: u16,
        version: String,
    },
    /// Peer Exchange (PEX): Share known peer addresses so nodes can connect across WAN/LAN
    PeerExchange {
        peers: Vec<SocketAddr>,
    },
    /// Anti-Entropy State Sync Request: Ask for all flagged file signatures
    SyncRequest,
    /// Anti-Entropy State Sync Response: Deliver all flagged file signatures
    SyncResponse {
        signatures: Vec<FileSignature>,
    },
    /// Real-Time Gossip Broadcast: A new file was flagged on the network
    GossipSignature {
        signature: FileSignature,
        origin_node: String,
        message_id: Uuid,
    },
    /// Connection Liveness
    Ping,
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    pub node_id: String,
    pub tcp_port: u16,
}
