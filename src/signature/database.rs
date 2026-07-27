use super::hasher::FileSignature;
use anyhow::Context;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::RwLock;

/// Thread-safe wrapper around SignatureDatabase for sharing between UI and Tokio P2P actor
#[derive(Clone)]
pub struct SharedSignatureDb {
    inner: Arc<RwLock<SignatureDatabase>>,
    disk_path: PathBuf,
}

impl SharedSignatureDb {
    pub fn new(disk_path: PathBuf) -> Self {
        let db = SignatureDatabase::load_from_disk(&disk_path);
        Self {
            inner: Arc::new(RwLock::new(db)),
            disk_path,
        }
    }

    pub fn insert_and_save(&self, sig: FileSignature) -> bool {
        let mut guard = self.inner.write();
        let added = guard.insert(sig);
        if added {
            let _ = guard.save_to_disk(&self.disk_path);
        }
        added
    }

    pub fn is_flagged(&self, blake3_hash: &str) -> Option<FileSignature> {
        self.inner.read().get(blake3_hash)
    }

    pub fn get_all_signatures(&self) -> Vec<FileSignature> {
        self.inner.read().get_all()
    }

    pub fn count(&self) -> usize {
        self.inner.read().count()
    }

    /// Merges incoming signatures from a remote P2P peer and saves to disk if any were new.
    /// Returns a list of newly added signatures.
    pub fn merge_from_peer(&self, incoming: Vec<FileSignature>) -> Vec<FileSignature> {
        let mut guard = self.inner.write();
        let new_items = guard.merge_signatures(incoming);
        if !new_items.is_empty() {
            let _ = guard.save_to_disk(&self.disk_path);
        }
        new_items
    }
}

#[derive(Debug, Default, Clone)]
pub struct SignatureDatabase {
    signatures: HashMap<String, FileSignature>,
}

impl SignatureDatabase {
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    pub fn insert(&mut self, sig: FileSignature) -> bool {
        if self.signatures.contains_key(&sig.blake3_hash) {
            false
        } else {
            self.signatures.insert(sig.blake3_hash.clone(), sig);
            true
        }
    }

    pub fn get(&self, hash: &str) -> Option<FileSignature> {
        self.signatures.get(hash).cloned()
    }

    pub fn get_all(&self) -> Vec<FileSignature> {
        let mut list: Vec<FileSignature> = self.signatures.values().cloned().collect();
        // Sort by flagged timestamp descending (newest first)
        list.sort_by(|a, b| b.flagged_at.cmp(&a.flagged_at));
        list
    }

    pub fn count(&self) -> usize {
        self.signatures.len()
    }

    pub fn merge_signatures(&mut self, incoming: Vec<FileSignature>) -> Vec<FileSignature> {
        let mut added = Vec::new();
        for sig in incoming {
            if !self.signatures.contains_key(&sig.blake3_hash) {
                let sig_clone = sig.clone();
                self.signatures.insert(sig.blake3_hash.clone(), sig);
                added.push(sig_clone);
            }
        }
        added
    }

    pub fn save_to_disk(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = File::create(path)
            .with_context(|| format!("Failed to create signature DB file at {}", path.display()))?;
        let writer = BufWriter::new(file);
        let list = self.get_all();
        serde_json::to_writer_pretty(writer, &list)
            .with_context(|| "Failed to serialize signatures JSON")?;
        Ok(())
    }

    pub fn load_from_disk(path: &Path) -> Self {
        if !path.exists() {
            return Self::new();
        }
        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return Self::new(),
        };
        let reader = BufReader::new(file);
        let list: Result<Vec<FileSignature>, _> = serde_json::from_reader(reader);
        match list {
            Ok(items) => {
                let mut db = Self::new();
                for item in items {
                    db.signatures.insert(item.blake3_hash.clone(), item);
                }
                db
            }
            Err(_) => Self::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_signature_database_operations() {
        let mut db = SignatureDatabase::new();
        let sig = FileSignature {
            blake3_hash: "abc123hash".to_string(),
            file_name: "malware.exe".to_string(),
            file_size: 1024,
            flagged_by_peer: "node-A".to_string(),
            flagged_at: chrono::Utc::now(),
            reason: "Manual Flag".to_string(),
            threat_level: "HIGH".to_string(),
        };

        // Insert
        assert!(db.insert(sig.clone()));
        assert!(!db.insert(sig.clone())); // duplicate should return false

        // Query
        assert!(db.get("abc123hash").is_some());
        assert!(db.get("nonexistent").is_none());

        // Save & reload
        let temp_file = NamedTempFile::new().unwrap();
        db.save_to_disk(temp_file.path()).unwrap();

        let loaded_db = SignatureDatabase::load_from_disk(temp_file.path());
        assert_eq!(loaded_db.get_all().len(), 1);
        assert!(loaded_db.get("abc123hash").is_some());
    }
}
