#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = <[u8; 2]>::try_from(data) {
        let _ = protonet::protocol::version::supports_major(u16::from_le_bytes(bytes));
    }
});
