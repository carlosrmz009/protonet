#![no_main]
use libfuzzer_sys::fuzz_target;
use libp2p::Multiaddr;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 512 {
        let _ = Multiaddr::try_from(data.to_vec());
        if let Ok(text) = std::str::from_utf8(data) {
            let _ = text.parse::<Multiaddr>();
        }
    }
});
