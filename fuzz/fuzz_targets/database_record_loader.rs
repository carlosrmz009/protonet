#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::protocol::FlaggedFileRecord;
use protonet::storage::SharedSignatureDb;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = FlaggedFileRecord::decode(data) {
        if let Ok(database) = SharedSignatureDb::in_memory() {
            let _ = database.insert_record(&record);
        }
    }
});
