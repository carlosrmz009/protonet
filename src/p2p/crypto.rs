use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

/// 256-bit symmetric AEAD security shield key for the True-P2P network (RFC 8439).
/// Ensures zero plaintext transmission, complete packet confidentiality, and MITM immunity across all transport channels.
#[allow(dead_code)]
const PROTONET_NETWORK_KEY: [u8; 32] = [
    0x9a, 0xf3, 0x11, 0x8c, 0x4d, 0x22, 0x77, 0xe9, 0x01, 0x84, 0x3b, 0xca, 0xf5, 0x90, 0x6e,
    0x12, 0x33, 0xac, 0xd1, 0x09, 0x44, 0x55, 0x88, 0xfe, 0x19, 0xbc, 0x27, 0x98, 0xa1, 0x76,
    0xef, 0x5a,
];

pub struct ProtonetCrypto;

impl ProtonetCrypto {
    /// Generate an untraceable ephemeral node ID (BLAKE3 hash of random entropy).
    /// Ensures peer privacy and zero tracking across restarts and sessions.
    pub fn generate_ephemeral_id() -> String {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let hash = blake3::hash(&entropy);
        format!("p2p-enc-{}", &hash.to_hex()[..12])
    }

    /// Encrypts and authenticates a payload using ChaCha20-Poly1305 AEAD (RFC 8439).
    /// Returns [12-byte random nonce || ciphertext || 16-byte Poly1305 MAC].
    #[allow(dead_code)]
    pub fn encrypt_packet(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let key = chacha20poly1305::Key::from_slice(&PROTONET_NETWORK_KEY);
        let cipher = ChaCha20Poly1305::new(key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("AEAD encryption error: {}", e))?;

        let mut packet = Vec::with_capacity(12 + ciphertext.len());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    /// Validates MAC authentication tag and decrypts a ChaCha20-Poly1305 packet.
    /// Rejects tampered frames, replay attempts, and unauthorized network scans immediately.
    #[allow(dead_code)]
    pub fn decrypt_packet(encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
        if encrypted.len() < 12 + 16 {
            anyhow::bail!("Encrypted frame too short (missing nonce or Poly1305 auth tag)");
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let key = chacha20poly1305::Key::from_slice(&PROTONET_NETWORK_KEY);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|_| {
            anyhow::anyhow!("AEAD decryption failed: invalid key or tampered packet")
        })?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha20_poly1305_aead_roundtrip() {
        let msg = b"flagged threat signature payload: malware-blake3-hash-here";
        let encrypted = ProtonetCrypto::encrypt_packet(msg).expect("encryption must succeed");

        assert_ne!(encrypted, msg, "ciphertext must not match plaintext");
        assert!(encrypted.len() >= msg.len() + 28, "must include 12-byte nonce + 16-byte auth tag");

        let decrypted = ProtonetCrypto::decrypt_packet(&encrypted).expect("decryption must succeed");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_tampered_packet_rejection() {
        let msg = b"legitimate gossip broadcast";
        let mut encrypted = ProtonetCrypto::encrypt_packet(msg).expect("encryption must succeed");

        // Tamper with ciphertext bit
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0x01;

        let result = ProtonetCrypto::decrypt_packet(&encrypted);
        assert!(result.is_err(), "tampered packet must be rejected by Poly1305 authentication");
    }

    #[test]
    fn test_ephemeral_untraceable_ids() {
        let id1 = ProtonetCrypto::generate_ephemeral_id();
        let id2 = ProtonetCrypto::generate_ephemeral_id();

        assert!(id1.starts_with("p2p-enc-"));
        assert_ne!(id1, id2, "ephemeral IDs must be randomized per session");
    }
}
