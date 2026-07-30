#![cfg(windows)]

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use protonet::network::{NetworkCommand, NetworkConfig, NetworkEvent, P2pEngine, P2pHandle};
use protonet::storage::SharedSignatureDb;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

static INTEGRATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Node {
    _root: TempDir,
    handle: P2pHandle,
    events: mpsc::Receiver<NetworkEvent>,
    database: SharedSignatureDb,
}

async fn start_node() -> Node {
    start_custom_node(
        vec![
            "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        ],
        Vec::new(),
        false,
    )
    .await
}

async fn start_custom_node(
    listen_addresses: Vec<Multiaddr>,
    relay_addresses: Vec<Multiaddr>,
    enable_relay_server: bool,
) -> Node {
    let root = tempfile::tempdir().unwrap();
    let database = SharedSignatureDb::try_new(root.path().join("records.sqlite3")).unwrap();
    let config = NetworkConfig {
        listen_addresses,
        bootstrap_peers: Vec::new(),
        relay_addresses,
        enable_mdns: false,
        enable_relay_server,
        sync_interval: Duration::from_secs(60),
        database_path: root.path().join("records.sqlite3"),
        identity_path: root.path().join("identity.dat"),
    };
    let (event_tx, events) = P2pEngine::event_channel();
    let handle = P2pEngine::spawn(config, database.clone(), event_tx)
        .await
        .unwrap();
    Node {
        _root: root,
        handle,
        events,
        database,
    }
}

async fn start_tcp_only_node() -> Node {
    start_custom_node(
        vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        Vec::new(),
        false,
    )
    .await
}

async fn start_discovery_node(bootstrap_peers: Vec<Multiaddr>, enable_mdns: bool) -> Node {
    let root = tempfile::tempdir().unwrap();
    let database = SharedSignatureDb::try_new(root.path().join("records.sqlite3")).unwrap();
    let config = NetworkConfig {
        listen_addresses: vec![
            "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
            "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
        ],
        bootstrap_peers,
        relay_addresses: Vec::new(),
        enable_mdns,
        enable_relay_server: false,
        sync_interval: Duration::from_secs(60),
        database_path: root.path().join("records.sqlite3"),
        identity_path: root.path().join("identity.dat"),
    };
    let (event_tx, events) = P2pEngine::event_channel();
    let handle = P2pEngine::spawn(config, database.clone(), event_tx)
        .await
        .unwrap();
    Node {
        _root: root,
        handle,
        events,
        database,
    }
}

async fn quic_listen(node: &mut Node) -> Multiaddr {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(NetworkEvent::Listening { address }) = node.events.recv().await {
                if address.to_string().contains("/quic-v1") {
                    return address;
                }
            }
        }
    })
    .await
    .expect("QUIC listener did not start")
}

async fn wait_connected(node: &mut Node, expected: PeerId) {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(NetworkEvent::PeerConnected { peer_id, .. }) = node.events.recv().await {
                if peer_id == expected {
                    return;
                }
            }
        }
    })
    .await
    .expect("authenticated connection was not established");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_and_tampered_tcp_do_not_establish_a_peer_session() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut node = start_tcp_only_node().await;
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(NetworkEvent::Listening { address }) = node.events.recv().await {
                return address;
            }
        }
    })
    .await
    .unwrap();
    let mut ip = None;
    let mut port = None;
    for protocol in address.iter() {
        match protocol {
            Protocol::Ip4(value) => ip = Some(value),
            Protocol::Tcp(value) => port = Some(value),
            _ => {}
        }
    }
    let mut stream = tokio::net::TcpStream::connect((ip.unwrap(), port.unwrap()))
        .await
        .unwrap();
    stream
        .write_all(br#"{"node_id":"forged","version":"plaintext"}"#)
        .await
        .unwrap();
    stream.write_all(&[0xff; 128]).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(node.handle.peer_count(), 0);
    let _ = node.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn relay_only_peers_establish_end_to_end_encrypted_circuit() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut relay = start_custom_node(
        vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        Vec::new(),
        true,
    )
    .await;
    let relay_id = relay.handle.local_peer_id().unwrap();
    let mut relay_address = quic_listen(&mut relay).await;
    relay_address.push(Protocol::P2p(relay_id));

    let mut first = start_custom_node(Vec::new(), vec![relay_address.clone()], false).await;
    let mut second = start_custom_node(Vec::new(), vec![relay_address], false).await;
    let first_id = first.handle.local_peer_id().unwrap();
    let second_id = second.handle.local_peer_id().unwrap();

    let mut second_circuit = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(NetworkEvent::Listening { address }) = second.events.recv().await {
                if address.to_string().contains("/p2p-circuit") {
                    return address;
                }
            }
        }
    })
    .await
    .expect("relay reservation did not produce a circuit address");
    if !matches!(second_circuit.iter().last(), Some(Protocol::P2p(peer)) if peer == second_id) {
        second_circuit.push(Protocol::P2p(second_id));
    }
    first
        .handle
        .cmd_tx
        .send(NetworkCommand::Connect(second_circuit))
        .await
        .unwrap();

    let directness = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(NetworkEvent::PeerConnected {
                peer_id,
                directness,
                ..
            }) = first.events.recv().await
            {
                if peer_id == second_id {
                    return directness;
                }
            }
        }
    })
    .await
    .expect("relay circuit did not connect");
    assert_eq!(
        directness,
        protonet::network::connection_manager::Directness::Relayed
    );
    assert_ne!(first_id, second_id);

    first
        .handle
        .cmd_tx
        .send(NetworkCommand::PublishFile {
            sha256: [11; 32],
            blake3: [12; 32],
            file_size: 12,
            file_name: Some("relay-only.bin".to_owned()),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while second.database.count() != 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("record did not cross the encrypted relay circuit");

    let _ = first.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
    let _ = second.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
    let _ = relay.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn two_lan_nodes_discover_each_other_with_mdns_without_subnet_scanning() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut first = start_discovery_node(Vec::new(), true).await;
    let mut second = start_discovery_node(Vec::new(), true).await;
    let first_id = first.handle.local_peer_id().unwrap();
    let second_id = second.handle.local_peer_id().unwrap();
    wait_connected(&mut first, second_id).await;
    wait_connected(&mut second, first_id).await;
    let _ = first.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
    let _ = second.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dht_discovered_peers_continue_after_bootstrap_shutdown() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut bootstrap = start_discovery_node(Vec::new(), false).await;
    let bootstrap_id = bootstrap.handle.local_peer_id().unwrap();
    let mut bootstrap_address = quic_listen(&mut bootstrap).await;
    let bootstrap_text = bootstrap_address
        .to_string()
        .replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/");
    bootstrap_address = bootstrap_text.parse().unwrap();
    bootstrap_address.push(Protocol::P2p(bootstrap_id));

    let mut first = start_discovery_node(vec![bootstrap_address.clone()], false).await;
    let mut second = start_discovery_node(vec![bootstrap_address], false).await;
    let first_id = first.handle.local_peer_id().unwrap();
    let second_id = second.handle.local_peer_id().unwrap();
    wait_connected(&mut first, bootstrap_id).await;
    wait_connected(&mut second, bootstrap_id).await;

    wait_connected(&mut first, second_id).await;
    wait_connected(&mut second, first_id).await;
    bootstrap
        .handle
        .cmd_tx
        .send(NetworkCommand::Shutdown)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    first
        .handle
        .cmd_tx
        .send(NetworkCommand::PublishFile {
            sha256: [21; 32],
            blake3: [22; 32],
            file_size: 22,
            file_name: Some("bootstrap-loss.bin".to_owned()),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while second.database.count() != 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("discovered peers stopped propagating after bootstrap shutdown");
    let _ = first.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
    let _ = second.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_reset_disconnects_and_restarts_with_a_new_authenticated_peer_id() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut node = start_node().await;
    let old = node.handle.local_peer_id().unwrap();
    node.handle
        .cmd_tx
        .send(NetworkCommand::ResetIdentity)
        .await
        .unwrap();
    let new = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if let Some(NetworkEvent::IdentityReset { peer_id }) = node.events.recv().await {
                return peer_id;
            }
        }
    })
    .await
    .expect("identity reset did not restart the swarm");
    assert_ne!(old, new);
    assert_eq!(node.handle.local_peer_id(), Some(new));
    assert_eq!(node.handle.peer_count(), 0);
    let _ = node.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_peers_propagate_and_partition_recovery_syncs_without_central_service() {
    let _guard = INTEGRATION_LOCK.lock().await;
    let mut first = start_node().await;
    let mut second = start_node().await;
    let first_id = first.handle.local_peer_id().unwrap();
    let second_id = second.handle.local_peer_id().unwrap();
    assert_ne!(first_id, second_id);
    let mut first_address = quic_listen(&mut first).await;
    let _ = quic_listen(&mut second).await;

    first
        .handle
        .cmd_tx
        .send(NetworkCommand::PublishFile {
            sha256: [1; 32],
            blake3: [2; 32],
            file_size: 42,
            file_name: Some("partitioned.bin".to_owned()),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while first.database.count() != 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("origin did not persist its record");

    first_address.push(Protocol::P2p(first_id));
    second
        .handle
        .cmd_tx
        .send(NetworkCommand::Connect(first_address))
        .await
        .unwrap();
    wait_connected(&mut second, first_id).await;
    wait_connected(&mut first, second_id).await;

    second
        .handle
        .cmd_tx
        .send(NetworkCommand::RequestSync(first_id))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while second.database.count() != 1 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("incremental peer sync did not converge");

    tokio::time::sleep(Duration::from_secs(2)).await;
    first
        .handle
        .cmd_tx
        .send(NetworkCommand::PublishFile {
            sha256: [3; 32],
            blake3: [4; 32],
            file_size: 84,
            file_name: Some("gossip.bin".to_owned()),
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        while second.database.count() != 2 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("signed gossip did not propagate");

    let _ = first.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
    let _ = second.handle.cmd_tx.send(NetworkCommand::Shutdown).await;
}
