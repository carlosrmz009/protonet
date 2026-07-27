use super::message::P2pMessage;
use crate::signature::{FileSignature, SharedSignatureDb};
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{debug, info};
use uuid::Uuid;

const BASE_TCP_PORT: u16 = 7778;
const TCP_PORTS_COUNT: u16 = 15;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum P2pCommand {
    ConnectRemote(SocketAddr),
    BroadcastGossip(FileSignature),
    RequestSync,
}

#[derive(Debug, Clone)]
pub enum P2pEvent {
    PeerConnected {
        addr: SocketAddr,
        node_id: String,
    },
    PeerDisconnected {
        addr: SocketAddr,
    },
    GossipReceived {
        signature: FileSignature,
        origin_node: String,
    },
    SyncCompleted {
        new_signatures_count: usize,
    },
    LogMessage(String),
}

#[derive(Clone)]
pub struct P2pHandle {
    pub node_id: String,
    pub listen_port: u16,
    pub cmd_tx: mpsc::Sender<P2pCommand>,
    pub connected_peers: Arc<Mutex<HashMap<SocketAddr, String>>>,
}

impl P2pHandle {
    pub fn peer_count(&self) -> usize {
        self.connected_peers.lock().len()
    }

    #[allow(dead_code)]
    pub fn get_peers_info(&self) -> Vec<(SocketAddr, String)> {
        self.connected_peers
            .lock()
            .iter()
            .map(|(&addr, id)| (addr, id.clone()))
            .collect()
    }
}

pub struct P2pEngine {
    node_id: String,
    shared_db: SharedSignatureDb,
    event_tx: mpsc::UnboundedSender<P2pEvent>,
    cmd_rx: mpsc::Receiver<P2pCommand>,
    connected_senders: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<P2pMessage>>>>,
    connected_peers_meta: Arc<Mutex<HashMap<SocketAddr, String>>>,
    seen_message_ids: Arc<Mutex<HashSet<Uuid>>>,
}

impl P2pEngine {
    pub async fn spawn(
        node_id: String,
        shared_db: SharedSignatureDb,
        event_tx: mpsc::UnboundedSender<P2pEvent>,
    ) -> anyhow::Result<P2pHandle> {
        let (cmd_tx, cmd_rx) = mpsc::channel(100);

        // Bind TCP Listener on first available port starting from BASE_TCP_PORT (7778)
        let mut listener = None;
        let mut bound_port = 0;

        for offset in 0..TCP_PORTS_COUNT {
            let candidate_port = BASE_TCP_PORT + offset;
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), candidate_port);
            if let Ok(l) = TcpListener::bind(addr).await {
                bound_port = candidate_port;
                listener = Some(l);
                break;
            }
        }

        let listener = match listener {
            Some(l) => l,
            None => {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
                let l = TcpListener::bind(addr).await?;
                bound_port = l.local_addr()?.port();
                l
            }
        };

        info!("Protonet P2P TCP Listener bound on port {}", bound_port);

        let connected_peers_meta = Arc::new(Mutex::new(HashMap::new()));
        let connected_senders = Arc::new(Mutex::new(HashMap::new()));
        let seen_message_ids = Arc::new(Mutex::new(HashSet::new()));

        let engine = Self {
            node_id: node_id.clone(),
            shared_db,
            event_tx,
            cmd_rx,
            connected_senders,
            connected_peers_meta: connected_peers_meta.clone(),
            seen_message_ids,
        };

        let handle = P2pHandle {
            node_id: node_id.clone(),
            listen_port: bound_port,
            cmd_tx,
            connected_peers: connected_peers_meta,
        };

        tokio::spawn(async move {
            engine.run(listener, bound_port).await;
        });

        Ok(handle)
    }

    async fn run(mut self, listener: TcpListener, my_port: u16) {
        let (disc_tx, mut disc_rx) = mpsc::channel(50);
        let _ = super::discovery::start_discovery_service(
            self.node_id.clone(),
            my_port,
            disc_tx,
        )
        .await;

        let _ = self.event_tx.send(P2pEvent::LogMessage(format!(
            "Node {} active. Listening on TCP port {}",
            self.node_id, my_port
        )));

        loop {
            tokio::select! {
                // 1. Inbound connection from remote peer
                accept_res = listener.accept() => {
                    if let Ok((stream, remote_addr)) = accept_res {
                        self.handle_new_connection(stream, remote_addr, my_port).await;
                    }
                }

                // 2. Local/LAN Auto-Discovery beacon received
                Some(candidate_addr) = disc_rx.recv() => {
                    self.try_connect_to_peer(candidate_addr, my_port).await;
                }

                // 3. UI Command (Connect, Broadcast Gossip, Request Sync)
                Some(cmd) = self.cmd_rx.recv() => {
                    self.handle_command(cmd, my_port).await;
                }
            }
        }
    }

    async fn handle_command(&self, cmd: P2pCommand, my_port: u16) {
        match cmd {
            P2pCommand::ConnectRemote(addr) => {
                let _ = self.event_tx.send(P2pEvent::LogMessage(format!(
                    "Attempting manual WAN connection to peer {}...",
                    addr
                )));
                self.try_connect_to_peer(addr, my_port).await;
            }
            P2pCommand::BroadcastGossip(signature) => {
                let message_id = Uuid::new_v4();
                self.seen_message_ids.lock().insert(message_id);

                let gossip = P2pMessage::GossipSignature {
                    signature: signature.clone(),
                    origin_node: self.node_id.clone(),
                    message_id,
                };

                self.broadcast_message(gossip).await;
                let _ = self.event_tx.send(P2pEvent::LogMessage(format!(
                    "Broadcasted FLAGGED signature for '{}' to network via Gossip.",
                    signature.file_name
                )));
            }
            P2pCommand::RequestSync => {
                let _ = self.event_tx.send(P2pEvent::LogMessage(
                    "Requesting Anti-Entropy Signature Sync from connected peers...".to_string(),
                ));
                self.broadcast_message(P2pMessage::SyncRequest).await;
            }
        }
    }

    async fn broadcast_message(&self, msg: P2pMessage) {
        let senders: Vec<_> = self.connected_senders.lock().values().cloned().collect();
        for tx in senders {
            let _ = tx.send(msg.clone()).await;
        }
    }

    async fn try_connect_to_peer(&self, remote_addr: SocketAddr, my_port: u16) {
        // Prevent self-connection or duplicates
        if self.connected_senders.lock().contains_key(&remote_addr) {
            return;
        }

        match TcpStream::connect(remote_addr).await {
            Ok(stream) => {
                self.handle_new_connection(stream, remote_addr, my_port).await;
            }
            Err(err) => {
                debug!("Failed to connect to candidate peer {}: {}", remote_addr, err);
            }
        }
    }

    async fn handle_new_connection(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        my_port: u16,
    ) {
        if self.connected_senders.lock().contains_key(&remote_addr) {
            return;
        }

        let (mut sender_sink, mut receiver_stream) =
            Framed::new(stream, LengthDelimitedCodec::new()).split();

        // Perform Handshake
        let handshake_msg = P2pMessage::Handshake {
            node_id: self.node_id.clone(),
            listen_port: my_port,
            version: "Protonet-0.1.0".to_string(),
        };

        let handshake_bytes = match serde_json::to_vec(&handshake_msg) {
            Ok(b) => bytes::Bytes::from(b),
            Err(_) => return,
        };

        if sender_sink.send(handshake_bytes).await.is_err() {
            return;
        }

        // Create outbound message channel for this connection
        let (peer_tx, mut peer_rx) = mpsc::channel::<P2pMessage>(50);
        self.connected_senders.lock().insert(remote_addr, peer_tx.clone());

        // Spawn outbound writer
        tokio::spawn(async move {
            while let Some(msg) = peer_rx.recv().await {
                if let Ok(bytes) = serde_json::to_vec(&msg) {
                    if sender_sink.send(bytes::Bytes::from(bytes)).await.is_err() {
                        break;
                    }
                }
            }
        });

        // Spawn inbound reader & state machine
        let _node_id = self.node_id.clone();
        let event_tx = self.event_tx.clone();
        let shared_db = self.shared_db.clone();
        let connected_senders = self.connected_senders.clone();
        let connected_peers_meta = self.connected_peers_meta.clone();
        let seen_ids = self.seen_message_ids.clone();

        tokio::spawn(async move {
            let mut peer_node_id = "unknown".to_string();

            // Send initial SyncRequest & PeerExchange upon connection
            let _ = peer_tx.send(P2pMessage::SyncRequest).await;

            while let Some(Ok(frame)) = receiver_stream.next().await {
                if let Ok(msg) = serde_json::from_slice::<P2pMessage>(&frame) {
                    match msg {
                        P2pMessage::Handshake {
                            node_id: remote_id, ..
                        } => {
                            peer_node_id = remote_id.clone();
                            connected_peers_meta
                                .lock()
                                .insert(remote_addr, remote_id.clone());
                            let _ = event_tx.send(P2pEvent::PeerConnected {
                                addr: remote_addr,
                                node_id: remote_id.clone(),
                            });
                            let _ = event_tx.send(P2pEvent::LogMessage(format!(
                                "Connected to peer {} ({})",
                                remote_id, remote_addr
                            )));
                        }
                        P2pMessage::SyncRequest => {
                            let all_sigs = shared_db.get_all_signatures();
                            let _ = peer_tx
                                .send(P2pMessage::SyncResponse {
                                    signatures: all_sigs,
                                })
                                .await;
                        }
                        P2pMessage::SyncResponse { signatures } => {
                            let new_items = shared_db.merge_from_peer(signatures);
                            if !new_items.is_empty() {
                                let _ = event_tx.send(P2pEvent::SyncCompleted {
                                    new_signatures_count: new_items.len(),
                                });
                                let _ = event_tx.send(P2pEvent::LogMessage(format!(
                                    "Anti-Entropy Sync: Auto-updated {} new flagged threat signatures!",
                                    new_items.len()
                                )));
                            }
                        }
                        P2pMessage::GossipSignature {
                            signature,
                            origin_node,
                            message_id,
                        } => {
                            let should_process = {
                                let mut ids_guard = seen_ids.lock();
                                if !ids_guard.contains(&message_id) {
                                    ids_guard.insert(message_id);
                                    true
                                } else {
                                    false
                                }
                            };

                            if should_process {
                                let added = shared_db.insert_and_save(signature.clone());
                                if added {
                                    let _ = event_tx.send(P2pEvent::GossipReceived {
                                        signature: signature.clone(),
                                        origin_node: origin_node.clone(),
                                    });
                                    let _ = event_tx.send(P2pEvent::LogMessage(format!(
                                        "⚡ GOSSIP ALERT: Received flagged file '{}' from origin {} (BLAKE3: {}...)",
                                        signature.file_name,
                                        origin_node,
                                        &signature.blake3_hash[..12]
                                    )));

                                    // Forward gossip to other peers (Gossipsub flood)
                                    let all_txs: Vec<_> = connected_senders
                                        .lock()
                                        .iter()
                                        .filter(|(&a, _)| a != remote_addr)
                                        .map(|(_, tx)| tx.clone())
                                        .collect();

                                    let forward_msg = P2pMessage::GossipSignature {
                                        signature,
                                        origin_node,
                                        message_id,
                                    };

                                    for tx in all_txs {
                                        let _ = tx.send(forward_msg.clone()).await;
                                    }
                                }
                            }
                        }
                        P2pMessage::PeerExchange { .. } | P2pMessage::Ping | P2pMessage::Pong => {}
                    }
                }
            }

            // Cleanup when stream closes
            connected_senders.lock().remove(&remote_addr);
            connected_peers_meta.lock().remove(&remote_addr);
            let _ = event_tx.send(P2pEvent::PeerDisconnected { addr: remote_addr });
            let _ = event_tx.send(P2pEvent::LogMessage(format!(
                "Disconnected from peer {} ({})",
                peer_node_id, remote_addr
            )));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::FileSignature;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_p2p_gossip_and_flagged_detection() {
        let file_a = NamedTempFile::new().unwrap();
        let file_b = NamedTempFile::new().unwrap();

        let shared_db_a = SharedSignatureDb::new(file_a.path().to_path_buf());
        let shared_db_b = SharedSignatureDb::new(file_b.path().to_path_buf());

        let (tx_a, mut rx_a) = mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = mpsc::unbounded_channel();

        let p2p_a = P2pEngine::spawn("node_a".to_string(), shared_db_a.clone(), tx_a)
            .await
            .unwrap();
        let p2p_b = P2pEngine::spawn("node_b".to_string(), shared_db_b.clone(), tx_b)
            .await
            .unwrap();

        // Connect Node A to Node B using B's listen_port
        let target_addr = format!("127.0.0.1:{}", p2p_b.listen_port)
            .parse()
            .unwrap();
        p2p_a
            .cmd_tx
            .send(P2pCommand::ConnectRemote(target_addr))
            .await
            .unwrap();

        // Wait a short moment for TCP handshake & Anti-Entropy sync
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Create a threat signature on Node A
        let threat_hash = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a";
        let sig = FileSignature {
            blake3_hash: threat_hash.to_string(),
            file_name: "ransomware_sample.exe".to_string(),
            file_size: 65536,
            flagged_by_peer: "node_a".to_string(),
            flagged_at: chrono::Utc::now(),
            reason: "P2P Flagged".to_string(),
            threat_level: "HIGH".to_string(),
        };

        // Node A saves it to its local db and broadcasts via gossip
        shared_db_a.insert_and_save(sig.clone());
        p2p_a
            .cmd_tx
            .send(P2pCommand::BroadcastGossip(sig.clone()))
            .await
            .unwrap();

        // Wait for Gossipsub delivery to Node B
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Verify Node B received the gossip and stored it in its signature database!
        let result_in_b = shared_db_b.is_flagged(threat_hash);
        assert!(
            result_in_b.is_some(),
            "Node B MUST have received the flagged signature via Gossip!"
        );

        let received_sig = result_in_b.unwrap();
        assert_eq!(received_sig.file_name, "ransomware_sample.exe");
        assert_eq!(received_sig.flagged_by_peer, "node_a");

        // Drain event channels
        while let Ok(_) = rx_a.try_recv() {}
        while let Ok(_) = rx_b.try_recv() {}
    }
}
