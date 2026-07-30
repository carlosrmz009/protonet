#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::SyncRequest;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4 * 1024 * 1024 {
        if let Ok((request, trailing)) = postcard::take_from_bytes::<SyncRequest>(data) {
            if trailing.is_empty() {
                let _ = request.validate();
            }
        }
    }
});
