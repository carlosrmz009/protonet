#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::SyncResponse;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4 * 1024 * 1024 {
        if let Ok((response, trailing)) = postcard::take_from_bytes::<SyncResponse>(data) {
            if trailing.is_empty() {
                let _ = response.validate_bounds();
            }
        }
    }
});
