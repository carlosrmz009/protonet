use libp2p::identity;
use libp2p::request_response::Codec;
use proptest::prelude::*;
use protonet::protocol::codec::SyncCodec;
use protonet::protocol::record::{
    unix_time_ms, FlaggedFileRecord, RecordValidation, RecordValidator, MAX_ENCODED_RECORD_SIZE,
};
use protonet::protocol::{SyncRequest, SyncResponse};

proptest! {
    #[test]
    fn arbitrary_record_bytes_never_panic_or_overallocate(data in proptest::collection::vec(any::<u8>(), 0..(MAX_ENCODED_RECORD_SIZE * 2))) {
        let result = std::panic::catch_unwind(|| FlaggedFileRecord::decode(&data));
        prop_assert!(result.is_ok());
        if data.len() > MAX_ENCODED_RECORD_SIZE {
            prop_assert_eq!(result.unwrap(), Err(RecordValidation::Oversized));
        }
    }

    #[test]
    fn arbitrary_sync_requests_never_bypass_absolute_record_limit(
        count in 257usize..5_000
    ) {
        let request = SyncRequest::GetRecords { ids: vec![[7; 32]; count] };
        prop_assert!(request.validate().is_err());
    }

    #[test]
    fn arbitrary_trailing_bytes_are_rejected(trailing in proptest::collection::vec(any::<u8>(), 1..128)) {
        let key = identity::Keypair::generate_ed25519();
        let record = FlaggedFileRecord::create(
            &key,
            1,
            unix_time_ms(),
            [1; 32],
            [2; 32],
            5,
            Some("sample.bin".to_owned()),
        ).unwrap();
        let mut encoded = record.encode().unwrap();
        encoded.extend(trailing);
        prop_assert_eq!(FlaggedFileRecord::decode(&encoded), Err(RecordValidation::Malformed));
    }
}

#[test]
fn forwarded_origin_fields_and_signature_are_immutable() {
    let key = identity::Keypair::generate_ed25519();
    let now = unix_time_ms();
    let record = FlaggedFileRecord::create(
        &key,
        9,
        now,
        [3; 32],
        [4; 32],
        99,
        Some("payload.exe".to_owned()),
    )
    .unwrap();
    let original_signature = record.signature.clone();
    let original_origin = record.origin_peer_id.clone();
    let decoded = RecordValidator::default()
        .validate_bytes(&record.encode().unwrap(), now)
        .unwrap();
    assert_eq!(decoded.signature, original_signature);
    assert_eq!(decoded.origin_peer_id, original_origin);
    assert_eq!(decoded.sequence, 9);
}

#[test]
fn sync_response_vectors_are_bounded() {
    let response = SyncResponse::RecordIds {
        ids: vec![[0; 32]; 2_001],
        next_cursor: None,
    };
    assert!(response.validate_bounds().is_err());
}

#[tokio::test]
async fn oversized_sync_frame_is_rejected_at_the_absolute_codec_bound() {
    let mut codec = SyncCodec;
    let protocol = libp2p::StreamProtocol::new("/protonet/sync/1.0.0");
    let mut input = futures::io::Cursor::new(vec![0_u8; 4 * 1024 * 1024 + 1]);
    let result = codec.read_request(&protocol, &mut input).await;
    assert!(result.is_err());
}
