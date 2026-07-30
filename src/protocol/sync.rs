use super::record::{FlaggedFileRecord, RecordId};
use super::version::PROTOCOL_VERSION;
use serde::{Deserialize, Serialize};

pub const MAX_BUCKETS: usize = 366;
pub const MAX_IDS_PER_RESPONSE: usize = 2_000;
pub const MAX_REQUESTED_RECORDS: usize = 256;
pub const MAX_RECORDS_PER_RESPONSE: usize = 256;
pub const MAX_SYNC_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SIMULTANEOUS_SYNC_PEERS: usize = 4;
pub const MAX_PENDING_SYNC_REQUESTS_PER_PEER: usize = 2;
pub const MAX_SYNC_DURATION_SECS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DatabaseState {
    pub generation: u64,
    pub record_count: u64,
    pub newest_created_at: i64,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketDigest {
    pub start_unix: i64,
    pub end_unix: i64,
    pub record_count: u32,
    pub digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySummary {
    pub protocol_version: u16,
    pub generation: u64,
    pub record_count: u64,
    pub oldest_timestamp: i64,
    pub newest_timestamp: i64,
    pub bucket_digests: Vec<BucketDigest>,
}

impl Default for InventorySummary {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            generation: 0,
            record_count: 0,
            oldest_timestamp: 0,
            newest_timestamp: 0,
            bucket_digests: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncRequest {
    GetInventory,
    GetRecordIds {
        bucket_start: i64,
        cursor: Option<RecordId>,
        limit: u16,
    },
    GetRecords {
        ids: Vec<RecordId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    TooLarge,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncResponse {
    Inventory(InventorySummary),
    RecordIds {
        ids: Vec<RecordId>,
        next_cursor: Option<RecordId>,
    },
    Records {
        records: Vec<FlaggedFileRecord>,
    },
    Busy {
        retry_after_ms: u32,
    },
    Error {
        code: SyncErrorCode,
    },
}

impl SyncRequest {
    pub fn validate(&self) -> Result<(), SyncErrorCode> {
        match self {
            Self::GetInventory => Ok(()),
            Self::GetRecordIds { limit, .. }
                if *limit > 0 && usize::from(*limit) <= MAX_IDS_PER_RESPONSE =>
            {
                Ok(())
            }
            Self::GetRecords { ids } if !ids.is_empty() && ids.len() <= MAX_REQUESTED_RECORDS => {
                Ok(())
            }
            _ => Err(SyncErrorCode::TooLarge),
        }
    }
}

impl SyncResponse {
    pub fn validate_bounds(&self) -> Result<(), SyncErrorCode> {
        match self {
            Self::Inventory(i) if i.bucket_digests.len() <= MAX_BUCKETS => Ok(()),
            Self::RecordIds { ids, .. } if ids.len() <= MAX_IDS_PER_RESPONSE => Ok(()),
            Self::Records { records } if records.len() <= MAX_RECORDS_PER_RESPONSE => Ok(()),
            Self::Busy { .. } | Self::Error { .. } => Ok(()),
            _ => Err(SyncErrorCode::TooLarge),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_cannot_be_requested_in_one_unbounded_response() {
        assert!(SyncRequest::GetRecords {
            ids: vec![[0; 32]; MAX_REQUESTED_RECORDS + 1]
        }
        .validate()
        .is_err());
        assert!(SyncRequest::GetRecordIds {
            bucket_start: 0,
            cursor: None,
            limit: (MAX_IDS_PER_RESPONSE + 1) as u16,
        }
        .validate()
        .is_err());
    }
}
