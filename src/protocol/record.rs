use crate::protocol::version::{supports_major, PROTOCOL_VERSION};
use libp2p::{identity, PeerId};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub type RecordId = [u8; 32];

pub const MAX_ENCODED_RECORD_SIZE: usize = 16 * 1024;
pub const MAX_FILENAME_BYTES: usize = 512;
pub const MAX_REASON_BYTES: usize = 256;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_PEER_ID_BYTES: usize = 128;
pub const MAX_PUBLIC_KEY_BYTES: usize = 256;
pub const DEFAULT_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
pub const MAX_LIFETIME_MS: i64 = 31 * 24 * 60 * 60 * 1_000;
pub const CLOCK_SKEW_MS: i64 = 15 * 60 * 1_000;

const RECORD_DOMAIN: &[u8] = b"PROTONET-RECORD-V1";
const SIGNATURE_DOMAIN: &[u8] = b"PROTONET-SIGNED-RECORD-V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ThreatLevel {
    Malicious = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UnsignedRecord {
    protocol_version: u16,
    origin_peer_id: Vec<u8>,
    origin_public_key: Vec<u8>,
    sequence: u64,
    created_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    sha256: [u8; 32],
    blake3: [u8; 32],
    file_size: u64,
    file_name: Option<String>,
    reason: String,
    threat_level: ThreatLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlaggedFileRecord {
    pub protocol_version: u16,
    pub record_id: RecordId,
    pub origin_peer_id: Vec<u8>,
    pub origin_public_key: Vec<u8>,
    pub sequence: u64,
    pub created_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub sha256: [u8; 32],
    pub blake3: [u8; 32],
    pub file_size: u64,
    pub file_name: Option<String>,
    pub reason: String,
    pub threat_level: ThreatLevel,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RecordValidation {
    #[error("record exceeds the maximum encoded size")]
    Oversized,
    #[error("malformed record")]
    Malformed,
    #[error("unsupported protocol major version")]
    UnsupportedVersion,
    #[error("field exceeds its configured bound")]
    FieldTooLarge,
    #[error("origin peer ID is invalid")]
    InvalidPeerId,
    #[error("origin public key does not match the peer ID")]
    ForgedOrigin,
    #[error("record ID does not match its contents")]
    ModifiedRecord,
    #[error("origin signature is invalid")]
    InvalidSignature,
    #[error("record has expired")]
    Expired,
    #[error("record creation time is too far in the future")]
    FutureDated,
    #[error("expiration precedes creation")]
    ImpossibleTimestamp,
    #[error("record lifetime exceeds the maximum")]
    ExcessiveLifetime,
}

impl FlaggedFileRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        keypair: &identity::Keypair,
        sequence: u64,
        created_at_unix_ms: i64,
        sha256: [u8; 32],
        blake3: [u8; 32],
        file_size: u64,
        file_name: Option<String>,
    ) -> Result<Self, RecordValidation> {
        let public = keypair.public();
        let origin_peer_id = PeerId::from_public_key(&public).to_bytes();
        let origin_public_key = public.encode_protobuf();
        let expires_at_unix_ms = created_at_unix_ms
            .checked_add(DEFAULT_LIFETIME_MS)
            .ok_or(RecordValidation::ImpossibleTimestamp)?;
        let mut record = Self {
            protocol_version: PROTOCOL_VERSION,
            record_id: [0; 32],
            origin_peer_id,
            origin_public_key,
            sequence,
            created_at_unix_ms,
            expires_at_unix_ms,
            sha256,
            blake3,
            file_size,
            file_name,
            reason: "Protonet collaborative demo".to_owned(),
            threat_level: ThreatLevel::Malicious,
            signature: Vec::new(),
        };
        record.check_field_bounds()?;
        record.record_id = record.calculate_record_id()?;
        let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
        signed.extend_from_slice(SIGNATURE_DOMAIN);
        signed.extend_from_slice(&record.record_id);
        record.signature = keypair
            .sign(&signed)
            .map_err(|_| RecordValidation::InvalidSignature)?;
        if record.encode()?.len() > MAX_ENCODED_RECORD_SIZE {
            return Err(RecordValidation::Oversized);
        }
        Ok(record)
    }

    pub fn encode(&self) -> Result<Vec<u8>, RecordValidation> {
        postcard::to_allocvec(self).map_err(|_| RecordValidation::Malformed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordValidation> {
        if bytes.len() > MAX_ENCODED_RECORD_SIZE {
            return Err(RecordValidation::Oversized);
        }
        let (record, remainder) =
            postcard::take_from_bytes(bytes).map_err(|_| RecordValidation::Malformed)?;
        if !remainder.is_empty() {
            return Err(RecordValidation::Malformed);
        }
        let record: Self = record;
        record.check_field_bounds()?;
        Ok(record)
    }

    pub fn origin_peer_id(&self) -> Result<PeerId, RecordValidation> {
        PeerId::from_bytes(&self.origin_peer_id).map_err(|_| RecordValidation::InvalidPeerId)
    }

    pub fn calculate_record_id(&self) -> Result<RecordId, RecordValidation> {
        let unsigned = UnsignedRecord {
            protocol_version: self.protocol_version,
            origin_peer_id: self.origin_peer_id.clone(),
            origin_public_key: self.origin_public_key.clone(),
            sequence: self.sequence,
            created_at_unix_ms: self.created_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
            sha256: self.sha256,
            blake3: self.blake3,
            file_size: self.file_size,
            file_name: self.file_name.clone(),
            reason: self.reason.clone(),
            threat_level: self.threat_level,
        };
        let encoded = postcard::to_allocvec(&unsigned).map_err(|_| RecordValidation::Malformed)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(RECORD_DOMAIN);
        hasher.update(&encoded);
        Ok(*hasher.finalize().as_bytes())
    }

    fn check_field_bounds(&self) -> Result<(), RecordValidation> {
        if self.origin_peer_id.len() > MAX_PEER_ID_BYTES
            || self.origin_public_key.len() > MAX_PUBLIC_KEY_BYTES
            || self.signature.len() > MAX_SIGNATURE_BYTES
            || self
                .file_name
                .as_ref()
                .is_some_and(|v| v.len() > MAX_FILENAME_BYTES)
            || self.reason.len() > MAX_REASON_BYTES
        {
            return Err(RecordValidation::FieldTooLarge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RecordValidator {
    pub clock_skew_ms: i64,
    pub max_lifetime_ms: i64,
}

impl Default for RecordValidator {
    fn default() -> Self {
        Self {
            clock_skew_ms: CLOCK_SKEW_MS,
            max_lifetime_ms: MAX_LIFETIME_MS,
        }
    }
}

impl RecordValidator {
    pub fn validate_bytes(
        &self,
        bytes: &[u8],
        now_unix_ms: i64,
    ) -> Result<FlaggedFileRecord, RecordValidation> {
        let record = FlaggedFileRecord::decode(bytes)?;
        self.validate(&record, now_unix_ms)?;
        Ok(record)
    }

    pub fn validate(
        &self,
        record: &FlaggedFileRecord,
        now_unix_ms: i64,
    ) -> Result<(), RecordValidation> {
        record.check_field_bounds()?;
        if !supports_major(record.protocol_version) {
            return Err(RecordValidation::UnsupportedVersion);
        }
        if record.expires_at_unix_ms < record.created_at_unix_ms {
            return Err(RecordValidation::ImpossibleTimestamp);
        }
        if record.expires_at_unix_ms - record.created_at_unix_ms > self.max_lifetime_ms {
            return Err(RecordValidation::ExcessiveLifetime);
        }
        if record.expires_at_unix_ms <= now_unix_ms {
            return Err(RecordValidation::Expired);
        }
        if record.created_at_unix_ms > now_unix_ms.saturating_add(self.clock_skew_ms) {
            return Err(RecordValidation::FutureDated);
        }
        if record.calculate_record_id()? != record.record_id {
            return Err(RecordValidation::ModifiedRecord);
        }
        let public = identity::PublicKey::try_decode_protobuf(&record.origin_public_key)
            .map_err(|_| RecordValidation::ForgedOrigin)?;
        if PeerId::from_public_key(&public).to_bytes() != record.origin_peer_id {
            return Err(RecordValidation::ForgedOrigin);
        }
        let mut signed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32);
        signed.extend_from_slice(SIGNATURE_DOMAIN);
        signed.extend_from_slice(&record.record_id);
        if !public.verify(&signed, &record.signature) {
            return Err(RecordValidation::InvalidSignature);
        }
        Ok(())
    }
}

pub fn unix_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> (identity::Keypair, FlaggedFileRecord, i64) {
        let key = identity::Keypair::generate_ed25519();
        let now = 1_800_000_000_000;
        let record =
            FlaggedFileRecord::create(&key, 1, now, [2; 32], [3; 32], 42, Some("x".into()))
                .unwrap();
        (key, record, now)
    }

    #[test]
    fn signed_record_roundtrip_and_forwarding_preserves_signature() {
        let (_, record, now) = valid();
        let encoded = record.encode().unwrap();
        let forwarded = RecordValidator::default()
            .validate_bytes(&encoded, now + 1)
            .unwrap();
        assert_eq!(forwarded.signature, record.signature);
        assert_eq!(forwarded.origin_peer_id, record.origin_peer_id);
    }

    #[test]
    fn modifications_and_forgery_are_rejected() {
        let (_, record, now) = valid();
        for mutate in [
            |r: &mut FlaggedFileRecord| r.blake3[0] ^= 1,
            |r: &mut FlaggedFileRecord| r.sha256[0] ^= 1,
            |r: &mut FlaggedFileRecord| r.file_name = Some("changed".into()),
        ] {
            let mut changed = record.clone();
            mutate(&mut changed);
            assert_eq!(
                RecordValidator::default().validate(&changed, now),
                Err(RecordValidation::ModifiedRecord)
            );
        }
        let other = identity::Keypair::generate_ed25519();
        let mut forged = record.clone();
        forged.origin_peer_id = PeerId::from(other.public()).to_bytes();
        forged.record_id = forged.calculate_record_id().unwrap();
        assert!(matches!(
            RecordValidator::default().validate(&forged, now),
            Err(RecordValidation::ForgedOrigin | RecordValidation::InvalidSignature)
        ));
        let mut bad_signature = record.clone();
        bad_signature.signature[0] ^= 1;
        assert_eq!(
            RecordValidator::default().validate(&bad_signature, now),
            Err(RecordValidation::InvalidSignature)
        );
    }

    #[test]
    fn timestamps_and_size_are_bounded() {
        let (_, mut record, now) = valid();
        record.created_at_unix_ms = now - DEFAULT_LIFETIME_MS;
        record.expires_at_unix_ms = now - 1;
        record.record_id = record.calculate_record_id().unwrap();
        assert_eq!(
            RecordValidator::default().validate(&record, now),
            Err(RecordValidation::Expired)
        );
        let (_, mut future, _) = valid();
        future.created_at_unix_ms = now + CLOCK_SKEW_MS + 1;
        future.expires_at_unix_ms = future.created_at_unix_ms + DEFAULT_LIFETIME_MS;
        future.record_id = future.calculate_record_id().unwrap();
        assert_eq!(
            RecordValidator::default().validate(&future, now),
            Err(RecordValidation::FutureDated)
        );
        assert_eq!(
            FlaggedFileRecord::decode(&vec![0; MAX_ENCODED_RECORD_SIZE + 1]),
            Err(RecordValidation::Oversized)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let (_, record, _) = valid();
        let mut encoded = record.encode().unwrap();
        encoded.push(0);
        assert_eq!(
            FlaggedFileRecord::decode(&encoded),
            Err(RecordValidation::Malformed)
        );
    }
}
