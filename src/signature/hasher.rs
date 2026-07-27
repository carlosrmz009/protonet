use anyhow::Context;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSignature {
    /// 64-character lowercase hex string of BLAKE3 hash
    pub blake3_hash: String,
    /// Name of the flagged file
    pub file_name: String,
    /// File size in bytes
    pub file_size: u64,
    /// Node / Peer ID that flagged this threat
    pub flagged_by_peer: String,
    /// UTC timestamp when flagged
    pub flagged_at: DateTime<Utc>,
    /// Threat description or flag reason
    pub reason: String,
    /// Severity classification (e.g., "HIGH - P2P CONFIRMED", "CRITICAL THREAT")
    pub threat_level: String,
}

impl FileSignature {
    /// Computes the BLAKE3 cryptographic hash and metadata for any file on disk.
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

    /// Formats file size into human readable string (e.g., "1.45 MB")
    #[allow(dead_code)]
    pub fn formatted_size(&self) -> String {
        format_bytes(self.file_size)
    }
}

/// Helper function to stream a file and compute its BLAKE3 hash without loading entire file into memory.
pub fn compute_file_hash_and_meta(path: &Path) -> anyhow::Result<(String, String, u64)> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open file for signature check: {}", path.display()))?;
    
    let metadata = file.metadata()?;
    let file_size = metadata.len();
    
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown_file")
        .to_string();

    let mut reader = BufReader::new(file);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536]; // 64 KB buffer

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .context("Error reading file stream for BLAKE3 hashing")?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash_hex = hasher.finalize().to_hex().to_string();
    Ok((hash_hex, file_name, file_size))
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

        let sig = FileSignature::from_file(
            temp_file.path(),
            "Node-Test-1",
            "Test Flag",
            "CRITICAL",
        )
        .unwrap();

        assert_eq!(sig.blake3_hash.len(), 64);
        assert_eq!(sig.flagged_by_peer, "Node-Test-1");
        assert!(sig.file_size > 0);
    }
}
