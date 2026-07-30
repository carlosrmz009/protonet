#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::record::{unix_time_ms, RecordValidator};

fuzz_target!(|data: &[u8]| {
    let _ = RecordValidator::default().validate_bytes(data, unix_time_ms());
});
