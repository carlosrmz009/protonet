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

    // Try joining standard SSDP/mDNS UDP multicast group so LAN firewalls allow packets
    if let Ok(mcast_addr) = "239.255.255.250".parse::<Ipv4Addr>() {
        let _ = listen_socket.join_multicast_v4(mcast_addr, Ipv4Addr::UNSPECIFIED);
    }

    // 2. Spawn Beacon Transmitter Task
    let tx_node_id = node_id.clone();
    let send_socket = listen_socket.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let beacon = DiscoveryBeacon {
                node_id: tx_node_id.clone(),
                tcp_port: my_tcp_port,
            };
            if let Ok(payload) = serde_json::to_vec(&beacon) {
                if let Ok(enc_payload) = crate::p2p::crypto::ProtonetCrypto::encrypt_packet(&payload)
                {
                    // Compute LAN Subnet Broadcast IP if possible (e.g. 192.168.1.255)
                    let mut broadcast_ips = vec![
                        Ipv4Addr::new(255, 255, 255, 255),
                        Ipv4Addr::new(239, 255, 255, 250),
                        Ipv4Addr::new(127, 0, 0, 1),
                    ];
                    if let Some(my_ip) = get_local_lan_ip() {
                        let oct = my_ip.octets();
                        broadcast_ips.push(Ipv4Addr::new(oct[0], oct[1], oct[2], 255));
                    }

                    for port_offset in 0..DISCOVERY_PORTS_COUNT {
                        let target_port = BASE_DISCOVERY_PORT + port_offset;
                        for &ip in &broadcast_ips {
                            let target = SocketAddr::new(IpAddr::V4(ip), target_port);
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
    let peer_discovered_tx_udp = peer_discovered_tx.clone();
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
                            if beacon.node_id != rx_node_id {
                                let candidate_tcp_addr =
                                    SocketAddr::new(remote_addr.ip(), beacon.tcp_port);
                                debug!(
                                    "Discovered peer {} at {}",
                                    beacon.node_id, candidate_tcp_addr
                                );
                                let _ = peer_discovered_tx_udp.send(candidate_tcp_addr).await;
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    });

    // 4. Spawn Zero-Configuration Background TCP LAN Subnet Sweep
    let peer_discovered_tx_tcp = peer_discovered_tx.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        loop {
            let my_ip_opt = get_local_lan_ip();
            let my_last_octet = my_ip_opt.map(|ip| ip.octets()[3]).unwrap_or(0);
            let subnets = get_candidate_subnets();

            for oct_prefix in subnets {
                let mut tasks = Vec::new();
                for i in 1..=254u8 {
                    if i == my_last_octet {
                        continue; // Skip ourselves
                    }
                    let target_ip = Ipv4Addr::new(oct_prefix[0], oct_prefix[1], oct_prefix[2], i);
                    let tx_chan = peer_discovered_tx_tcp.clone();
                    for offset in 0..6 {
                        let target_addr = SocketAddr::new(
                            IpAddr::V4(target_ip),
                            crate::p2p::node::BASE_TCP_PORT + offset,
                        );
                        let tx_chan = tx_chan.clone();
                        tasks.push(tokio::spawn(async move {
                            if let Ok(Ok(_)) = tokio::time::timeout(
                                Duration::from_millis(250),
                                tokio::net::TcpStream::connect(target_addr),
                            )
                            .await
                            {
                                let _ = tx_chan.send(target_addr).await;
                            }
                        }));
                    }
                }
                for task in tasks {
                    let _ = task.await;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    Ok(())
}

/// Discovers local LAN IPv4 address via routing table probes across multiple target IPs.
fn get_local_lan_ip() -> Option<Ipv4Addr> {
    let targets = ["8.8.8.8:80", "192.168.1.1:80", "192.168.0.1:80", "10.0.0.1:80"];
    for target in targets {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if socket.connect(target).is_ok() {
                if let Ok(addr) = socket.local_addr() {
                    if let IpAddr::V4(ip) = addr.ip() {
                        if !ip.is_loopback() {
                            return Some(ip);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Returns detected LAN subnets plus standard home/office fallback subnets.
fn get_candidate_subnets() -> Vec<[u8; 3]> {
    let mut subnets = Vec::new();
    if let Some(ip) = get_local_lan_ip() {
        let oct = ip.octets();
        subnets.push([oct[0], oct[1], oct[2]]);
    }
    for default_sub in [[192, 168, 1], [192, 168, 0], [10, 0, 0]] {
        if !subnets.contains(&default_sub) {
            subnets.push(default_sub);
        }
    }
    subnets
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum WanRendezvousMessage {
    Announce {
        node_id: String,
        tcp_port: u16,
    },
    GossipSignature {
        signature: crate::signature::FileSignature,
        origin_node: String,
    },
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

pub async fn send_wan_gossip(sig: crate::signature::FileSignature, origin_node: String) {
    let msg = WanRendezvousMessage::GossipSignature {
        signature: sig,
        origin_node,
    };
    if let Ok(json_bytes) = serde_json::to_vec(&msg) {
        if let Ok(enc_bytes) = crate::p2p::crypto::ProtonetCrypto::encrypt_packet(&json_bytes) {
            let hex_body = encode_hex(&enc_bytes);
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap_or_default();
                let _ = client
                    .post("https://ntfy.sh/protonet_true_p2p_wan_v15")
                    .body(hex_body)
                    .send()
                    .await;
            });
        }
    }
}

pub async fn start_wan_rendezvous_service(
    node_id: String,
    my_tcp_port: u16,
    shared_db: crate::signature::SharedSignatureDb,
    event_tx: mpsc::UnboundedSender<crate::p2p::P2pEvent>,
    connected_peers: Arc<parking_lot::Mutex<std::collections::HashMap<SocketAddr, String>>>,
) {
    let tx_node_id = node_id.clone();
    let rx_node_id = node_id.clone();

    // 1. WAN Announcer Task (Announces encrypted presence to global topic every 6 seconds)
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap_or_default();
        let mut interval = tokio::time::interval(Duration::from_secs(6));
        loop {
            interval.tick().await;
            let msg = WanRendezvousMessage::Announce {
                node_id: tx_node_id.clone(),
                tcp_port: my_tcp_port,
            };
            if let Ok(json_bytes) = serde_json::to_vec(&msg) {
                if let Ok(enc_bytes) =
                    crate::p2p::crypto::ProtonetCrypto::encrypt_packet(&json_bytes)
                {
                    let hex_body = encode_hex(&enc_bytes);
                    let _ = client
                        .post("https://ntfy.sh/protonet_true_p2p_wan_v15")
                        .body(hex_body)
                        .send()
                        .await;
                }
            }
        }
    });

    // 2. WAN Receiver & NAT Relay Task (Polls global topic every 4 seconds)
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .build()
            .unwrap_or_default();
        let mut interval = tokio::time::interval(Duration::from_secs(4));
        let mut seen_ids = std::collections::HashSet::new();
        loop {
            interval.tick().await;
            if let Ok(resp) = client
                .get("https://ntfy.sh/protonet_true_p2p_wan_v15/json?since=20m&poll=1")
                .send()
                .await
            {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                            if let Some(msg_str) = val.get("message").and_then(|m| m.as_str()) {
                                if let Ok(enc_bytes) = decode_hex(msg_str.trim()) {
                                    if let Ok(dec_bytes) =
                                        crate::p2p::crypto::ProtonetCrypto::decrypt_packet(&enc_bytes)
                                    {
                                        if let Ok(wan_msg) =
                                            serde_json::from_slice::<WanRendezvousMessage>(&dec_bytes)
                                        {
                                            match wan_msg {
                                                WanRendezvousMessage::Announce {
                                                    node_id: remote_id,
                                                    tcp_port,
                                                } => {
                                                    if remote_id != rx_node_id
                                                        && !seen_ids.contains(&remote_id)
                                                    {
                                                        seen_ids.insert(remote_id.clone());
                                                        let dummy_addr = SocketAddr::new(
                                                            IpAddr::V4(Ipv4Addr::new(
                                                                100,
                                                                64,
                                                                0,
                                                                (seen_ids.len() % 250 + 1) as u8,
                                                            )),
                                                            tcp_port,
                                                        );
                                                        connected_peers
                                                            .lock()
                                                            .insert(dummy_addr, remote_id.clone());
                                                        let _ = event_tx.send(
                                                            crate::p2p::P2pEvent::PeerConnected {
                                                                addr: dummy_addr,
                                                                node_id: remote_id.clone(),
                                                            },
                                                        );
                                                        let _ = event_tx.send(
                                                            crate::p2p::P2pEvent::LogMessage(
                                                                format!(
                                                                    "wan  :: + discovered peer {} via global WAN rendezvous",
                                                                    remote_id
                                                                ),
                                                            ),
                                                        );
                                                    }
                                                }
                                                WanRendezvousMessage::GossipSignature {
                                                    signature,
                                                    origin_node,
                                                } => {
                                                    if origin_node != rx_node_id {
                                                        let inserted = shared_db
                                                            .insert_and_save(signature.clone());
                                                        if inserted {
                                                            let _ = event_tx.send(
                                                                crate::p2p::P2pEvent::GossipReceived {
                                                                    signature: signature.clone(),
                                                                    origin_node: origin_node.clone(),
                                                                },
                                                            );
                                                            let _ = event_tx.send(
                                                                crate::p2p::P2pEvent::LogMessage(
                                                                    format!(
                                                                        "wan  :: + synced signature '{}' over WAN NAT tunnel",
                                                                        signature.file_name
                                                                    ),
                                                                ),
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}
