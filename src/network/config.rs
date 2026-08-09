use libp2p::Multiaddr;
use std::path::PathBuf;
use std::time::Duration;

pub const MAX_BOOTSTRAP_PEERS: usize = 64;
pub const MAX_ADDRESS_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<Multiaddr>,
    pub relay_addresses: Vec<Multiaddr>,
    pub enable_mdns: bool,
    pub enable_relay_server: bool,
    pub allow_private_test_network: bool,
    pub sync_records_response_delay: Duration,
    pub sync_interval: Duration,
    pub database_path: PathBuf,
    pub identity_path: PathBuf,
}

impl NetworkConfig {
    pub fn production_default() -> anyhow::Result<Self> {
        let dirs = directories::ProjectDirs::from("", "", "Protonet")
            .ok_or_else(|| anyhow::anyhow!("application data directory unavailable"))?;
        let data = dirs.data_local_dir();
        Ok(Self {
            listen_addresses: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".parse()?,
                "/ip6/::/udp/0/quic-v1".parse()?,
                "/ip4/0.0.0.0/tcp/0".parse()?,
                "/ip6/::/tcp/0".parse()?,
            ],
            bootstrap_peers: bootstrap_from_env(),
            relay_addresses: relay_from_env(),
            enable_mdns: mdns_allowed_for_current_profile(),
            enable_relay_server: std::env::var("PROTONET_RELAY_SERVER")
                .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")),
            allow_private_test_network: false,
            sync_records_response_delay: Duration::ZERO,
            sync_interval: Duration::from_secs(5 * 60),
            database_path: data.join("records.sqlite3"),
            identity_path: data.join("identity.dat"),
        })
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.bootstrap_peers.len() > MAX_BOOTSTRAP_PEERS {
            anyhow::bail!("too many bootstrap peers");
        }
        for address in self
            .listen_addresses
            .iter()
            .chain(&self.bootstrap_peers)
            .chain(&self.relay_addresses)
        {
            if address.to_vec().len() > MAX_ADDRESS_BYTES {
                anyhow::bail!("multiaddress exceeds maximum length");
            }
        }
        Ok(())
    }
}

fn bootstrap_from_env() -> Vec<Multiaddr> {
    addresses_from_env("PROTONET_BOOTSTRAP_PEERS")
}

fn relay_from_env() -> Vec<Multiaddr> {
    addresses_from_env("PROTONET_RELAY_PEERS")
}

fn addresses_from_env(name: &str) -> Vec<Multiaddr> {
    std::env::var(name)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(';')
                .take(MAX_BOOTSTRAP_PEERS)
                .filter(|item| item.len() <= MAX_ADDRESS_BYTES)
                .filter_map(|item| item.trim().parse().ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

fn mdns_allowed_for_current_profile() -> bool {
    if let Ok(value) = std::env::var("PROTONET_MDNS") {
        return value == "1" || value.eq_ignore_ascii_case("true");
    }
    #[cfg(windows)]
    {
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-NetConnectionProfile | Where-Object IPv4Connectivity -ne 'Disconnected').NetworkCategory",
            ])
            .output();
        output
            .ok()
            .filter(|result| result.status.success())
            .and_then(|result| String::from_utf8(result.stdout).ok())
            .is_some_and(|profiles| {
                let values: Vec<_> = profiles
                    .lines()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .collect();
                !values.is_empty()
                    && values
                        .iter()
                        .all(|value| *value == "Private" || *value == "DomainAuthenticated")
            })
    }
    #[cfg(not(windows))]
    {
        false
    }
}

pub fn peer_from_address(address: &Multiaddr) -> Option<libp2p::PeerId> {
    address.iter().last().and_then(|protocol| match protocol {
        libp2p::multiaddr::Protocol::P2p(peer) => Some(peer),
        _ => None,
    })
}

pub fn prefer_quic(addresses: &mut [Multiaddr]) {
    addresses.sort_by_key(|address| {
        let text = address.to_string();
        if text.contains("/quic-v1") {
            0
        } else if text.contains("/tcp/") && !text.contains("/p2p-circuit") {
            1
        } else if text.contains("/p2p-circuit") {
            2
        } else {
            3
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_preference_is_quic_then_noise_tcp_then_relay() {
        let mut values = vec![
            "/ip4/127.0.0.1/tcp/1/p2p-circuit".parse().unwrap(),
            "/ip4/127.0.0.1/tcp/2".parse().unwrap(),
            "/ip4/127.0.0.1/udp/3/quic-v1".parse().unwrap(),
        ];
        prefer_quic(&mut values);
        assert!(values[0].to_string().contains("quic-v1"));
        assert!(values[1].to_string().contains("/tcp/2"));
        assert!(values[2].to_string().contains("p2p-circuit"));
    }
}
