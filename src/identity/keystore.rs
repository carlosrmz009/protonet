use anyhow::{bail, Context};
use libp2p::{identity, PeerId};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

const FILE_MAGIC: &[u8; 16] = b"PROTONET-DPAPI1\0";
const DPAPI_DESCRIPTION: &str = "Protonet libp2p Ed25519 identity";

#[derive(Clone)]
pub struct StoredIdentity {
    pub keypair: identity::Keypair,
    pub peer_id: PeerId,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct IdentityStore {
    path: PathBuf,
}

impl IdentityStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn default_path() -> anyhow::Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("", "", "Protonet")
            .context("Windows application-data directory is unavailable")?;
        Ok(dirs.data_local_dir().join("identity.dat"))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_or_create(&self) -> anyhow::Result<StoredIdentity> {
        if self.path.exists() {
            return self.load();
        }
        self.generate_and_store()
    }

    pub fn load(&self) -> anyhow::Result<StoredIdentity> {
        let stored = fs::read(&self.path)
            .with_context(|| format!("failed to read {}", self.path.display()))?;
        if stored.len() <= FILE_MAGIC.len() || &stored[..FILE_MAGIC.len()] != FILE_MAGIC {
            bail!("invalid Protonet identity file header");
        }
        let plaintext = unprotect(&stored[FILE_MAGIC.len()..])
            .context("Windows DPAPI could not decrypt the Protonet identity")?;
        let keypair = identity::Keypair::from_protobuf_encoding(&plaintext)
            .context("decrypted identity is malformed")?;
        let peer_id = PeerId::from_public_key(&keypair.public());
        Ok(StoredIdentity {
            keypair,
            peer_id,
            path: self.path.clone(),
        })
    }

    pub fn reset(&self) -> anyhow::Result<StoredIdentity> {
        if self.path.exists() {
            fs::remove_file(&self.path)
                .with_context(|| format!("failed to delete {}", self.path.display()))?;
        }
        self.generate_and_store()
    }

    fn generate_and_store(&self) -> anyhow::Result<StoredIdentity> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _lock = CreationLock::acquire(&self.path)?;
        if self.path.exists() {
            return self.load();
        }
        let keypair = identity::Keypair::generate_ed25519();
        let plaintext = keypair
            .to_protobuf_encoding()
            .context("failed to serialize Ed25519 identity")?;
        let protected = protect(&plaintext).context("Windows DPAPI identity encryption failed")?;
        let mut bytes = Vec::with_capacity(FILE_MAGIC.len() + protected.len());
        bytes.extend_from_slice(FILE_MAGIC);
        bytes.extend_from_slice(&protected);
        if !atomic_create(&self.path, &bytes)? {
            return self.load();
        }
        let peer_id = PeerId::from_public_key(&keypair.public());
        Ok(StoredIdentity {
            keypair,
            peer_id,
            path: self.path.clone(),
        })
    }
}

struct CreationLock {
    path: PathBuf,
}

impl CreationLock {
    fn acquire(identity_path: &Path) -> anyhow::Result<Self> {
        let parent = identity_path
            .parent()
            .context("identity path has no parent")?;
        let name = identity_path
            .file_name()
            .context("identity path has no file name")?
            .to_string_lossy();
        let path = parent.join(format!(".{name}.lock"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())?;
                    file.sync_all()?;
                    return Ok(Self { path });
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    if std::time::Instant::now() >= deadline {
                        bail!("timed out waiting for identity creation lock");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

impl Drop for CreationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn atomic_create(path: &Path, bytes: &[u8]) -> anyhow::Result<bool> {
    let parent = path.parent().context("identity path has no parent")?;
    let temp_path = parent.join(format!(
        ".identity-{}-{}.tmp",
        std::process::id(),
        blake3::hash(bytes).to_hex()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(true),
        Err(_error) if path.exists() => {
            let _ = fs::remove_file(&temp_path);
            Ok(false)
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            Err(error.into())
        }
    }
}

#[cfg(windows)]
fn protect(plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext
            .len()
            .try_into()
            .context("identity is too large")?,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let description: Vec<u16> = DPAPI_DESCRIPTION.encode_utf16().chain(Some(0)).collect();
    let ok = unsafe {
        CryptProtectData(
            &input,
            description.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        LocalFree(output.pbData as *mut core::ffi::c_void);
        result
    };
    Ok(result)
}

#[cfg(windows)]
fn unprotect(ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext
            .len()
            .try_into()
            .context("identity is too large")?,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let result = slice.to_vec();
        LocalFree(output.pbData as *mut core::ffi::c_void);
        result
    };
    Ok(result)
}

#[cfg(not(windows))]
fn protect(_: &[u8]) -> anyhow::Result<Vec<u8>> {
    bail!("Protonet identity persistence requires Windows DPAPI")
}

#[cfg(not(windows))]
fn unprotect(_: &[u8]) -> anyhow::Result<Vec<u8>> {
    bail!("Protonet identity persistence requires Windows DPAPI")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn identities_are_unique_persistent_and_not_plaintext() {
        let root = tempdir().unwrap();
        let first_store = IdentityStore::new(root.path().join("one.dat"));
        let second_store = IdentityStore::new(root.path().join("two.dat"));
        let first = first_store.load_or_create().unwrap();
        let second = second_store.load_or_create().unwrap();
        assert_ne!(first.peer_id, second.peer_id);
        assert_eq!(first.peer_id, first_store.load_or_create().unwrap().peer_id);

        let plaintext = first.keypair.to_protobuf_encoding().unwrap();
        let disk = fs::read(first_store.path()).unwrap();
        assert!(!disk
            .windows(plaintext.len())
            .any(|window| window == plaintext));
        assert!(disk.starts_with(FILE_MAGIC));
    }

    #[test]
    fn reset_creates_a_new_peer_id() {
        let root = tempdir().unwrap();
        let store = IdentityStore::new(root.path().join("identity.dat"));
        let old = store.load_or_create().unwrap().peer_id;
        let new = store.reset().unwrap().peer_id;
        assert_ne!(old, new);
    }

    #[test]
    fn malformed_identity_never_panics_or_loads() {
        let root = tempdir().unwrap();
        let path = root.path().join("identity.dat");
        fs::write(&path, b"not an identity").unwrap();
        assert!(IdentityStore::new(path).load().is_err());
    }

    #[test]
    fn concurrent_creation_uses_the_persisted_winner() {
        let root = tempdir().unwrap();
        let path = root.path().join("identity.dat");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let path = path.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                IdentityStore::new(path).load_or_create().unwrap().peer_id
            }));
        }
        let peers: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(peers.iter().all(|peer| peer == &peers[0]));
        assert_eq!(IdentityStore::new(path).load().unwrap().peer_id, peers[0]);
    }
}
