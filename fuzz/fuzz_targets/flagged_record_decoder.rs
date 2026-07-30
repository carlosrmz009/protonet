#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::FlaggedFileRecord;

fuzz_target!(|data: &[u8]| {
    let _ = FlaggedFileRecord::decode(data);
});
