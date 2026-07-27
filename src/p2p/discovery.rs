use super::message::DiscoveryBeacon;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info};

const BASE_DISCOVERY_PORT: u16 = 7777;
const DISCOVERY_PORTS_COUNT: u16 = 10; // Scan ports 7777..7786 for multi-instance / LAN

/// Starts the UDP Broadcast Auto-Discovery Service.
/// Spawns background tasks to send periodic beacons and listen for incoming beacons from other Protonet peers.
pub async fn start_discovery_service(
    node_id: String,
    my_tcp_port: u16,
    peer_discovered_tx: mpsc::Sender<SocketAddr>,
) -> anyhow::Result<()> {
    // 1. Find an available UDP listen port in the discovery range (7777..7786)
    let mut listen_socket = None;
    let mut bound_port = 0;

    for port_offset in 0..DISCOVERY_PORTS_COUNT {
        let candidate_port = BASE_DISCOVERY_PORT + port_offset;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), candidate_port);
        if let Ok(socket) = UdpSocket::bind(addr).await {
            let _ = socket.set_broadcast(true);
            bound_port = candidate_port;
            listen_socket = Some(socket);
            break;
        }
    }

    let listen_socket = match listen_socket {
        Some(s) => Arc::new(s),
        None => {
            // Fallback to any ephemeral port if range is busy
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let s = UdpSocket::bind(addr).await?;
            let _ = s.set_broadcast(true);
            bound_port = s.local_addr()?.port();
            Arc::new(s)
        }
    };

    info!(
        "Protonet UDP LAN/Local Discovery active on UDP port {}",
        bound_port
    );

    // 2. Spawn Beacon Transmitter Task
    let tx_node_id = node_id.clone();
    let send_socket = listen_socket.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3));
        loop {
            interval.tick().await;
            let beacon = DiscoveryBeacon {
                node_id: tx_node_id.clone(),
                tcp_port: my_tcp_port,
            };
            if let Ok(payload) = serde_json::to_vec(&beacon) {
                if let Ok(enc_payload) = crate::p2p::crypto::ProtonetCrypto::encrypt_packet(&payload)
                {
                    // Broadcast to LAN broadcast address and local ports
                    for port_offset in 0..DISCOVERY_PORTS_COUNT {
                        let target_port = BASE_DISCOVERY_PORT + port_offset;
                        let targets = [
                            SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                                target_port,
                            ),
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), target_port),
                        ];
                        for &target in &targets {
                            let _ = send_socket.send_to(&enc_payload, target).await;
                        }
                    }
                }
            }
        }
    });

    // 3. Spawn Beacon Receiver Task
    let rx_node_id = node_id.clone();
    let recv_socket = listen_socket.clone();
    tokio::spawn(async move {
        let mut buffer = [0u8; 1024];
        loop {
            match recv_socket.recv_from(&mut buffer).await {
                Ok((len, remote_addr)) => {
                    if let Ok(dec_bytes) =
                        crate::p2p::crypto::ProtonetCrypto::decrypt_packet(&buffer[..len])
                    {
                        if let Ok(beacon) =
                            serde_json::from_slice::<DiscoveryBeacon>(&dec_bytes)
                        {
                            // Skip beacons from ourselves
                            if beacon.node_id != rx_node_id && beacon.tcp_port != my_tcp_port {
                                let candidate_tcp_addr =
                                    SocketAddr::new(remote_addr.ip(), beacon.tcp_port);
                                debug!(
                                    "Discovered peer {} at {}",
                                    beacon.node_id, candidate_tcp_addr
                                );
                                let _ = peer_discovered_tx.send(candidate_tcp_addr).await;
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    });

    Ok(())
}
