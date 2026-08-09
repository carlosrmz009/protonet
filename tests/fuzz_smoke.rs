use protonet::protocol::record::{unix_time_ms, FlaggedFileRecord, RecordValidator};
use protonet::protocol::{InventorySummary, SyncRequest, SyncResponse};

#[test]
fn scheduled_decoder_fuzz_smoke_covers_arbitrary_inputs() {
    let mut state = 0x9e3779b97f4a7c15_u64;
    let validator = RecordValidator::default();
    for iteration in 0..10_000_usize {
        let length = iteration % 16_384;
        let mut input = vec![0_u8; length];
        for byte in &mut input {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let _ = FlaggedFileRecord::decode(&input);
        let _ = validator.validate_bytes(&input, unix_time_ms());
        let _ = postcard::from_bytes::<SyncRequest>(&input);
        let _ = postcard::from_bytes::<SyncResponse>(&input);
        let _ = postcard::from_bytes::<InventorySummary>(&input);
        let text = String::from_utf8_lossy(&input);
        let _ = text.parse::<libp2p::Multiaddr>();
        let _ = libp2p::identity::Keypair::from_protobuf_encoding(&input);
    }
}
