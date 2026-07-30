#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::InventorySummary;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 4 * 1024 * 1024 {
        let _: Result<(InventorySummary, &[u8]), _> = postcard::take_from_bytes(data);
    }
});
