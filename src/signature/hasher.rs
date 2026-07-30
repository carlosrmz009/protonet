use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSignature {
    pub blake3_hash: String,
    pub file_name: String,
    pub file_size: u64,
    pub flagged_by_peer: String,
    pub flagged_at: DateTime<Utc>,
    pub reason: String,
    pub threat_level: String,
}

impl FileSignature {
    pub fn from_file(
        path: &Path,
        peer_id: &str,
        reason: &str,
        threat_level: &str,
    ) -> anyhow::Result<Self> {
        let (hash_hex, file_name, file_size) = compute_file_hash_and_meta(path)?;

        Ok(Self {
            blake3_hash: hash_hex,
            file_name,
            file_size,
            flagged_by_peer: peer_id.to_string(),
            flagged_at: Utc::now(),
            reason: reason.to_string(),
            threat_level: threat_level.to_string(),
        })
    }

    #[allow(dead_code)]
    pub fn formatted_size(&self) -> String {
        format_bytes(self.file_size)
    }
}

pub fn compute_file_hash_and_meta(path: &Path) -> anyhow::Result<(String, String, u64)> {
    let (_, blake3, file_name, file_size) = compute_file_hashes_and_meta(path)?;
    Ok((hex(&blake3), file_name, file_size))
}

pub fn compute_file_hashes_and_meta(
    path: &Path,
) -> anyhow::Result<([u8; 32], [u8; 32], String, u64)> {
    let file = File::open(path).with_context(|| {
        format!(
            "Failed to open file for signature check: {}",
            path.display()
        )
    })?;

    let metadata = file.metadata()?;
    let file_size = metadata.len();

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_file")
        .to_string();

    let mut reader = BufReader::new(file);
    let mut blake3_hasher = blake3::Hasher::new();
    let mut sha256_hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .context("Error reading file stream for BLAKE3 hashing")?;
        if bytes_read == 0 {
            break;
        }
        blake3_hasher.update(&buffer[..bytes_read]);
        sha256_hasher.update(&buffer[..bytes_read]);
    }

    let blake3 = *blake3_hasher.finalize().as_bytes();
    let sha256: [u8; 32] = sha256_hasher.finalize().into();
    Ok((sha256, blake3, file_name, file_size))
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    result
}

#[allow(dead_code)]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_signature_generation() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "protonet-test-threat-payload").unwrap();

        let sig =
            FileSignature::from_file(temp_file.path(), "Node-Test-1", "Test Flag", "CRITICAL")
                .unwrap();

        assert_eq!(sig.blake3_hash.len(), 64);
        assert_eq!(sig.flagged_by_peer, "Node-Test-1");
        assert!(sig.file_size > 0);
    }
}
