use crate::network::limits::{
    MAX_CONNECTED_PEERS, MAX_CONNECTIONS_PER_PEER, MAX_INBOUND_CONNECTIONS,
    MAX_OUTBOUND_CONNECTIONS, MAX_PENDING_INBOUND_HANDSHAKES, MAX_PENDING_OUTBOUND_DIALS,
};
use crate::protocol::codec::SyncCodec;
use crate::protocol::record::{FlaggedFileRecord, MAX_ENCODED_RECORD_SIZE};
use crate::protocol::version::{
    AGENT_VERSION, GOSSIP_PROTOCOL, INVENTORY_PROTOCOL, RECORDS_PROTOCOL, SYNC_PROTOCOL,
};
use libp2p::{
    autonat, connection_limits, dcutr, gossipsub, identify, identity, kad, mdns, ping, relay,
    request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour},
    PeerId, StreamProtocol,
};
use std::convert::Infallible;
use std::num::NonZeroUsize;
use std::time::Duration;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
pub struct ProtonetBehaviour {
    pub relay_client: relay::client::Behaviour,
    pub relay_server: Toggle<relay::Behaviour>,
    pub gossipsub: gossipsub::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
    pub autonat: autonat::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub sync: request_response::Behaviour<SyncCodec>,
    pub connection_limits: connection_limits::Behaviour,
}

impl ProtonetBehaviour {
    pub fn new(
        keypair: &identity::Keypair,
        relay_client: relay::client::Behaviour,
        enable_mdns: bool,
        enable_relay_server: bool,
        enable_peer_scoring: bool,
    ) -> anyhow::Result<Self> {
        let peer_id = PeerId::from_public_key(&keypair.public());
        let topic = gossipsub::IdentTopic::new(crate::protocol::version::GOSSIP_TOPIC);
        let mut gossip_config = gossipsub::ConfigBuilder::default();
        gossip_config
            .protocol_id_prefix(GOSSIP_PROTOCOL)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .validate_messages()
            .max_transmit_size(MAX_ENCODED_RECORD_SIZE)
            .mesh_n(6)
            .mesh_n_low(4)
            .mesh_n_high(12)
            .heartbeat_interval(Duration::from_secs(1))
            .message_id_fn(|message| {
                let id = FlaggedFileRecord::decode(&message.data)
                    .map(|record| record.record_id)
                    .unwrap_or_else(|_| *blake3::hash(&message.data).as_bytes());
                gossipsub::MessageId::from(id.to_vec())
            });
        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossip_config.build()?,
        )
        .map_err(|error| anyhow::anyhow!(error))?;
        if enable_peer_scoring {
            let mut score = gossipsub::PeerScoreParams::default();
            let mut topic_score = gossipsub::TopicScoreParams::default();
            topic_score.mesh_message_deliveries_weight = -1.0;
            topic_score.mesh_message_deliveries_window = Duration::from_secs(60);
            topic_score.mesh_message_deliveries_activation = Duration::from_secs(30);
            topic_score.mesh_message_deliveries_cap = 100.0;
            score.topics.insert(topic.hash(), topic_score);
            gossipsub
                .with_peer_score(score, gossipsub::PeerScoreThresholds::default())
                .map_err(anyhow::Error::msg)?;
        }
        gossipsub.subscribe(&topic)?;

        let store = kad::store::MemoryStore::with_config(
            peer_id,
            kad::store::MemoryStoreConfig {
                max_records: 1_024,
                max_value_bytes: 4 * 1_024,
                max_providers_per_key: 20,
                max_provided_keys: 256,
            },
        );
        let mut kad_config = kad::Config::new(StreamProtocol::new("/protonet/kad/1.0.0"));
        kad_config
            .set_query_timeout(Duration::from_secs(30))
            .set_max_packet_size(16 * 1024)
            .set_kbucket_size(NonZeroUsize::new(20).expect("non-zero"))
            .set_periodic_bootstrap_interval(Some(Duration::from_secs(10 * 60)));
        let kad = kad::Behaviour::with_config(peer_id, store, kad_config);

        let mdns = if enable_mdns {
            Some(mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            )?)
        } else {
            None
        };

        let identify = identify::Behaviour::new(
            identify::Config::new("/protonet/1.0.0".to_owned(), keypair.public())
                .with_agent_version(AGENT_VERSION.to_owned())
                .with_interval(Duration::from_secs(5 * 60)),
        );
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(30))
                .with_timeout(Duration::from_secs(10)),
        );
        let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
        let dcutr = dcutr::Behaviour::new(peer_id);

        let sync = request_response::Behaviour::with_codec(
            SyncCodec,
            [
                (
                    StreamProtocol::new(SYNC_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                ),
                (
                    StreamProtocol::new(INVENTORY_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                ),
                (
                    StreamProtocol::new(RECORDS_PROTOCOL),
                    request_response::ProtocolSupport::Full,
                ),
            ],
            request_response::Config::default()
                .with_request_timeout(Duration::from_secs(60))
                .with_max_concurrent_streams(16),
        );

        let relay_server = enable_relay_server.then(|| {
            let config = relay::Config {
                max_reservations: 128,
                max_reservations_per_peer: 1,
                max_circuits: 256,
                max_circuits_per_peer: 2,
                max_circuit_duration: Duration::from_secs(2 * 60),
                max_circuit_bytes: 32 * 1024 * 1024,
                ..relay::Config::default()
            };
            relay::Behaviour::new(peer_id, config)
        });

        let limits = connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(MAX_PENDING_INBOUND_HANDSHAKES))
            .with_max_pending_outgoing(Some(MAX_PENDING_OUTBOUND_DIALS))
            .with_max_established_incoming(Some(MAX_INBOUND_CONNECTIONS))
            .with_max_established_outgoing(Some(MAX_OUTBOUND_CONNECTIONS))
            .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER))
            .with_max_established(Some(MAX_CONNECTED_PEERS as u32));

        Ok(Self {
            relay_client,
            relay_server: Toggle::from(relay_server),
            gossipsub,
            kad,
            mdns: Toggle::from(mdns),
            identify,
            ping,
            autonat,
            dcutr,
            sync,
            connection_limits: connection_limits::Behaviour::new(limits),
        })
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum BehaviourEvent {
    RelayClient(relay::client::Event),
    RelayServer(relay::Event),
    Gossipsub(gossipsub::Event),
    Kad(kad::Event),
    Mdns(mdns::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Sync(request_response::Event<crate::protocol::SyncRequest, crate::protocol::SyncResponse>),
    ConnectionLimits(Infallible),
}

macro_rules! from_event {
    ($type:ty, $variant:ident) => {
        impl From<$type> for BehaviourEvent {
            fn from(value: $type) -> Self {
                Self::$variant(value)
            }
        }
    };
}

from_event!(relay::client::Event, RelayClient);
from_event!(relay::Event, RelayServer);
from_event!(gossipsub::Event, Gossipsub);
from_event!(kad::Event, Kad);
from_event!(mdns::Event, Mdns);
from_event!(identify::Event, Identify);
from_event!(ping::Event, Ping);
from_event!(autonat::Event, Autonat);
from_event!(dcutr::Event, Dcutr);
from_event!(
    request_response::Event<crate::protocol::SyncRequest, crate::protocol::SyncResponse>,
    Sync
);
from_event!(Infallible, ConnectionLimits);
