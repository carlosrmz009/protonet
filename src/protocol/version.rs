pub const PROTOCOL_VERSION: u16 = 1;
pub const AGENT_VERSION: &str = concat!("protonet/", env!("CARGO_PKG_VERSION"));
pub const GOSSIP_PROTOCOL: &str = "/protonet/gossip/1.0.0";
pub const SYNC_PROTOCOL: &str = "/protonet/sync/1.0.0";
pub const INVENTORY_PROTOCOL: &str = "/protonet/inventory/1.0.0";
pub const RECORDS_PROTOCOL: &str = "/protonet/records/1.0.0";
pub const GOSSIP_TOPIC: &str = "protonet.flagged-files.v1";

pub fn supports_major(version: u16) -> bool {
    version == PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_major_versions() {
        assert!(supports_major(1));
        assert!(!supports_major(0));
        assert!(!supports_major(2));
        assert!(!supports_major(u16::MAX));
    }
}
