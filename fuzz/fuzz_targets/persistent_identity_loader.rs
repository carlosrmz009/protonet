#![no_main]
use libfuzzer_sys::fuzz_target;
use protonet::identity::IdentityStore;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(root) = tempfile::tempdir() {
        let path = root.path().join("identity.dat");
        if std::fs::write(&path, data).is_ok() {
            let _ = IdentityStore::new(path).load();
        }
    }
});
