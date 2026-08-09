pub mod database;
pub mod hasher;

#[allow(unused_imports)]
pub use database::{SharedSignatureDb, SignatureDatabase};
#[allow(unused_imports)]
pub use hasher::{
    compute_file_hash_and_meta, compute_file_hashes_and_meta, compute_file_hashes_with_progress,
    format_bytes, FileSignature,
};
