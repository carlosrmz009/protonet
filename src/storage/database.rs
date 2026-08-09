use crate::network::limits::{
    MAX_ACTIVE_RECORDS, MAX_DAILY_NEW_RECORDS, MAX_DATABASE_BYTES, MIN_FREE_DISK_BYTES,
};
use crate::protocol::record::{unix_time_ms, ThreatLevel};
use crate::protocol::sync::{
    MAX_BUCKETS, MAX_IDS_PER_RESPONSE, MAX_RECORDS_PER_RESPONSE, MAX_REQUESTED_RECORDS,
};
use crate::protocol::{BucketDigest, DatabaseState, FlaggedFileRecord, InventorySummary, RecordId};
use crate::signature::hasher::{hex, FileSignature};
use anyhow::{bail, Context};
use chrono::{TimeZone, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DAY_MS: i64 = 86_400_000;

#[derive(Clone)]
pub struct SharedSignatureDb {
    inner: Arc<Mutex<SignatureDatabase>>,
}

pub struct SignatureDatabase {
    connection: Connection,
    path: PathBuf,
}

impl SharedSignatureDb {
    pub fn new(path: PathBuf) -> Self {
        Self::try_new(path).expect("failed to initialize Protonet SQLite database")
    }

    pub fn try_new(path: PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(SignatureDatabase::open(path)?)),
        })
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(SignatureDatabase::in_memory()?)),
        })
    }

    pub fn insert_record(&self, record: &FlaggedFileRecord) -> anyhow::Result<bool> {
        self.inner.lock().insert_record(record)
    }

    pub fn insert_batch(&self, records: &[FlaggedFileRecord]) -> anyhow::Result<Vec<bool>> {
        self.inner.lock().insert_batch(records)
    }

    pub fn remove_and_save(&self, hash: &str) -> bool {
        self.inner.lock().remove_blake3(hash).unwrap_or(false)
    }

    pub fn is_flagged(&self, blake3_hash: &str) -> Option<FileSignature> {
        self.inner.lock().get_by_blake3(blake3_hash).ok().flatten()
    }

    pub fn get_all_signatures(&self) -> Vec<FileSignature> {
        self.inner.lock().get_all().unwrap_or_default()
    }

    pub fn get_signatures_page(&self, offset: usize, limit: usize) -> Vec<FileSignature> {
        self.inner
            .lock()
            .get_page(offset, limit.min(100))
            .unwrap_or_default()
    }

    pub fn count(&self) -> usize {
        self.inner.lock().count().unwrap_or(0)
    }

    pub fn state(&self) -> anyhow::Result<DatabaseState> {
        self.inner.lock().state()
    }

    pub fn inventory(&self, now_ms: i64) -> anyhow::Result<InventorySummary> {
        self.inner.lock().inventory(now_ms)
    }

    pub fn record_ids(
        &self,
        bucket_start: i64,
        cursor: Option<RecordId>,
        limit: usize,
        now_ms: i64,
    ) -> anyhow::Result<(Vec<RecordId>, Option<RecordId>)> {
        self.inner
            .lock()
            .record_ids(bucket_start, cursor, limit, now_ms)
    }

    pub fn records_by_ids(&self, ids: &[RecordId]) -> anyhow::Result<Vec<FlaggedFileRecord>> {
        self.inner.lock().records_by_ids(ids)
    }

    pub fn next_local_sequence(&self, peer: &libp2p::PeerId) -> anyhow::Result<u64> {
        self.inner.lock().next_local_sequence(peer)
    }

    pub fn clear_identity_state(&self) -> anyhow::Result<()> {
        self.inner.lock().clear_identity_state()
    }

    pub fn cleanup_expired(&self, now_ms: i64) -> anyhow::Result<usize> {
        self.inner.lock().cleanup_expired(now_ms)
    }

    pub fn recent_replay_seeds(
        &self,
        limit: usize,
        now_ms: i64,
    ) -> anyhow::Result<Vec<(RecordId, libp2p::PeerId, u64)>> {
        self.inner.lock().recent_replay_seeds(limit, now_ms)
    }

    pub fn database_size_bytes(&self) -> u64 {
        total_database_size(self.inner.lock().path())
    }

    pub fn origin_highest_sequences(&self) -> anyhow::Result<Vec<(libp2p::PeerId, u64)>> {
        self.inner.lock().origin_highest_sequences()
    }

    pub fn active_record_ids(&self, now_ms: i64) -> anyhow::Result<Vec<RecordId>> {
        self.inner.lock().active_record_ids(now_ms)
    }

    pub fn storage_safety_status(&self) -> anyhow::Result<StorageSafetyStatus> {
        self.inner.lock().storage_safety_status()
    }
}

#[derive(Debug, Clone)]
pub struct StorageSafetyStatus {
    pub safe: bool,
    pub reason: Option<String>,
    pub database_size_bytes: u64,
    pub active_records: usize,
    pub available_disk_bytes: u64,
}

impl SignatureDatabase {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(&path)?;
        let auto_vacuum: i64 = connection.query_row("PRAGMA auto_vacuum", [], |row| row.get(0))?;
        if auto_vacuum != 2 {
            connection.execute_batch(
                "PRAGMA journal_mode = DELETE; PRAGMA auto_vacuum = INCREMENTAL; VACUUM;",
            )?;
        }
        connection.execute_batch(crate::storage::migrations::SCHEMA)?;
        Ok(Self { connection, path })
    }

    pub fn in_memory() -> anyhow::Result<Self> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(crate::storage::migrations::SCHEMA)?;
        Ok(Self {
            connection,
            path: PathBuf::from(":memory:"),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn insert_record(&mut self, record: &FlaggedFileRecord) -> anyhow::Result<bool> {
        Ok(self
            .insert_batch(std::slice::from_ref(record))?
            .into_iter()
            .next()
            .unwrap_or(false))
    }

    pub fn insert_batch(&mut self, records: &[FlaggedFileRecord]) -> anyhow::Result<Vec<bool>> {
        self.ensure_capacity(records)?;
        let tx = self.connection.transaction()?;
        let mut results = Vec::with_capacity(records.len());
        let mut changed = false;
        let mut inserted_count = 0_u64;
        for record in records.iter().take(100) {
            let inserted = insert_one(&tx, record)?;
            changed |= inserted;
            inserted_count = inserted_count.saturating_add(u64::from(inserted));
            results.push(inserted);
        }
        if changed {
            increment_generation(&tx)?;
            let day = unix_time_ms().div_euclid(DAY_MS);
            tx.execute(
                "INSERT INTO ingestion_daily(day, record_count) VALUES (?1, ?2)
                 ON CONFLICT(day) DO UPDATE SET record_count = record_count + excluded.record_count",
                params![day, i64::try_from(inserted_count)?],
            )?;
        }
        tx.commit()?;
        Ok(results)
    }

    pub fn remove_blake3(&mut self, hash: &str) -> anyhow::Result<bool> {
        let bytes = decode_hash(hash).context("invalid BLAKE3 hash")?;
        let tx = self.connection.transaction()?;
        let changed = tx.execute("DELETE FROM records WHERE blake3 = ?1", [bytes.as_slice()])? > 0;
        if changed {
            increment_generation(&tx)?;
        }
        tx.commit()?;
        Ok(changed)
    }

    pub fn get_by_blake3(&self, hash: &str) -> anyhow::Result<Option<FileSignature>> {
        let bytes = decode_hash(hash).context("invalid BLAKE3 hash")?;
        self.connection
            .query_row(
                "SELECT encoded_record FROM records WHERE blake3 = ?1 LIMIT 1",
                [bytes.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|encoded| decode_record(&encoded).map(to_file_signature))
            .transpose()
    }

    pub fn get_all(&self) -> anyhow::Result<Vec<FileSignature>> {
        let mut statement = self
            .connection
            .prepare("SELECT encoded_record FROM records ORDER BY created_at DESC")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut result = Vec::new();
        for row in rows {
            if let Ok(record) = decode_record(&row?) {
                result.push(to_file_signature(record));
            }
        }
        Ok(result)
    }

    pub fn get_page(&self, offset: usize, limit: usize) -> anyhow::Result<Vec<FileSignature>> {
        let mut statement = self.connection.prepare(
            "SELECT encoded_record FROM records ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = statement.query_map(
            params![i64::try_from(limit)?, i64::try_from(offset)?],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut result = Vec::with_capacity(limit);
        for row in rows {
            if let Ok(record) = decode_record(&row?) {
                result.push(to_file_signature(record));
            }
        }
        Ok(result)
    }

    pub fn count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM records", [], |row| row.get(0))?;
        Ok(count.max(0) as usize)
    }

    fn active_count(&self, now_ms: i64) -> anyhow::Result<usize> {
        let count: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM records WHERE expires_at > ?1",
            [now_ms],
            |row| row.get(0),
        )?;
        Ok(count.max(0) as usize)
    }

    pub fn state(&self) -> anyhow::Result<DatabaseState> {
        let generation = read_u64_metadata(&self.connection, "generation")?.unwrap_or(0);
        let (record_count, newest): (i64, Option<i64>) = self.connection.query_row(
            "SELECT COUNT(*), MAX(created_at) FROM records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let mut statement = self
            .connection
            .prepare("SELECT record_id FROM records ORDER BY record_id")?;
        let ids = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut digest = blake3::Hasher::new();
        for id in ids {
            digest.update(&id?);
        }
        Ok(DatabaseState {
            generation,
            record_count: record_count.max(0) as u64,
            newest_created_at: newest.unwrap_or(0),
            digest: *digest.finalize().as_bytes(),
        })
    }

    pub fn inventory(&self, now_ms: i64) -> anyhow::Result<InventorySummary> {
        let generation = read_u64_metadata(&self.connection, "generation")?.unwrap_or(0);
        let mut statement = self.connection.prepare(
            "SELECT (created_at / ?1) * ?1 AS bucket, record_id
             FROM records WHERE expires_at > ?2
             ORDER BY bucket, record_id",
        )?;
        let rows = statement.query_map(params![DAY_MS, now_ms], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut buckets: Vec<BucketDigest> = Vec::new();
        let mut current_start = None;
        let mut current_count = 0_u32;
        let mut current_hasher = blake3::Hasher::new();
        for row in rows {
            let (start, id) = row?;
            if current_start.is_some_and(|value| value != start) {
                let old = current_start.expect("checked");
                buckets.push(BucketDigest {
                    start_unix: old,
                    end_unix: old + DAY_MS,
                    record_count: current_count,
                    digest: *current_hasher.finalize().as_bytes(),
                });
                if buckets.len() >= MAX_BUCKETS {
                    break;
                }
                current_count = 0;
                current_hasher = blake3::Hasher::new();
            }
            current_start = Some(start);
            current_count = current_count.saturating_add(1);
            current_hasher.update(&id);
        }
        if let Some(start) = current_start {
            if buckets.len() < MAX_BUCKETS {
                buckets.push(BucketDigest {
                    start_unix: start,
                    end_unix: start + DAY_MS,
                    record_count: current_count,
                    digest: *current_hasher.finalize().as_bytes(),
                });
            }
        }
        let record_count = buckets.iter().map(|b| u64::from(b.record_count)).sum();
        Ok(InventorySummary {
            protocol_version: crate::protocol::version::PROTOCOL_VERSION,
            generation,
            record_count,
            oldest_timestamp: buckets.first().map(|b| b.start_unix).unwrap_or(0),
            newest_timestamp: buckets.last().map(|b| b.end_unix).unwrap_or(0),
            bucket_digests: buckets,
        })
    }

    pub fn record_ids(
        &self,
        bucket_start: i64,
        cursor: Option<RecordId>,
        limit: usize,
        now_ms: i64,
    ) -> anyhow::Result<(Vec<RecordId>, Option<RecordId>)> {
        let limit = limit.min(MAX_IDS_PER_RESPONSE);
        if limit == 0 {
            bail!("record ID limit must be non-zero");
        }
        let cursor_bytes = cursor.unwrap_or([0; 32]);
        let mut statement = self.connection.prepare(
            "SELECT record_id FROM records
             WHERE created_at >= ?1 AND created_at < ?2 AND expires_at > ?3 AND record_id > ?4
             ORDER BY record_id LIMIT ?5",
        )?;
        let rows = statement.query_map(
            params![
                bucket_start,
                bucket_start.saturating_add(DAY_MS),
                now_ms,
                cursor_bytes.as_slice(),
                (limit + 1) as i64
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut all = Vec::new();
        for row in rows {
            if let Ok(id) = <[u8; 32]>::try_from(row?.as_slice()) {
                all.push(id);
            }
        }
        let next_cursor = if all.len() > limit {
            all.truncate(limit);
            all.last().copied()
        } else {
            None
        };
        Ok((all, next_cursor))
    }

    pub fn records_by_ids(&self, ids: &[RecordId]) -> anyhow::Result<Vec<FlaggedFileRecord>> {
        if ids.len() > MAX_REQUESTED_RECORDS {
            bail!("too many requested records");
        }
        let mut statement = self.connection.prepare(
            "SELECT encoded_record FROM records WHERE record_id = ?1 AND expires_at > ?2",
        )?;
        let now = unix_time_ms();
        let mut result = Vec::with_capacity(ids.len().min(MAX_RECORDS_PER_RESPONSE));
        for id in ids.iter().take(MAX_RECORDS_PER_RESPONSE) {
            let encoded = statement
                .query_row(params![id.as_slice(), now], |row| row.get::<_, Vec<u8>>(0))
                .optional()?;
            if let Some(encoded) = encoded {
                if let Ok(record) = decode_record(&encoded) {
                    result.push(record);
                }
            }
        }
        Ok(result)
    }

    pub fn next_local_sequence(&mut self, peer: &libp2p::PeerId) -> anyhow::Result<u64> {
        let key = format!("sequence:{}", peer);
        let tx = self.connection.transaction()?;
        let current = read_u64_metadata(&tx, &key)?.unwrap_or(0);
        let next = current.checked_add(1).context("local sequence exhausted")?;
        write_u64_metadata(&tx, &key, next)?;
        tx.commit()?;
        Ok(next)
    }

    pub fn clear_identity_state(&mut self) -> anyhow::Result<()> {
        self.connection
            .execute("DELETE FROM metadata WHERE key LIKE 'sequence:%'", [])?;
        Ok(())
    }

    pub fn cleanup_expired(&mut self, now_ms: i64) -> anyhow::Result<usize> {
        let tx = self.connection.transaction()?;
        let changed = tx.execute("DELETE FROM records WHERE expires_at <= ?1", [now_ms])?;
        if changed > 0 {
            increment_generation(&tx)?;
        }
        tx.commit()?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum(2048);")?;
        self.connection.execute(
            "DELETE FROM ingestion_daily WHERE day < ?1",
            [now_ms.div_euclid(DAY_MS).saturating_sub(31)],
        )?;
        Ok(changed)
    }

    pub fn storage_safety_status(&self) -> anyhow::Result<StorageSafetyStatus> {
        let database_size_bytes = total_database_size(&self.path);
        let active_records = self.active_count(unix_time_ms())?;
        let available_disk_bytes = available_disk_bytes(&self.path);
        let reason = if database_size_bytes >= MAX_DATABASE_BYTES {
            Some("database byte limit reached".to_owned())
        } else if active_records >= MAX_ACTIVE_RECORDS {
            Some("active record limit reached".to_owned())
        } else if available_disk_bytes < MIN_FREE_DISK_BYTES {
            Some("free disk reserve reached".to_owned())
        } else {
            None
        };
        Ok(StorageSafetyStatus {
            safe: reason.is_none(),
            reason,
            database_size_bytes,
            active_records,
            available_disk_bytes,
        })
    }

    pub fn origin_highest_sequences(&self) -> anyhow::Result<Vec<(libp2p::PeerId, u64)>> {
        let mut statement = self
            .connection
            .prepare("SELECT origin_peer_id, highest_sequence FROM origin_sequences LIMIT ?1")?;
        let rows = statement.query_map([i64::try_from(MAX_ACTIVE_RECORDS)?], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut values = Vec::new();
        for row in rows {
            let (peer, sequence) = row?;
            if let (Ok(peer), Ok(sequence)) =
                (libp2p::PeerId::from_bytes(&peer), u64::try_from(sequence))
            {
                values.push((peer, sequence));
            }
        }
        Ok(values)
    }

    pub fn active_record_ids(&self, now_ms: i64) -> anyhow::Result<Vec<RecordId>> {
        let mut statement = self
            .connection
            .prepare("SELECT record_id FROM records WHERE expires_at > ?1 LIMIT ?2")?;
        let rows = statement
            .query_map(params![now_ms, i64::try_from(MAX_ACTIVE_RECORDS)?], |row| {
                row.get::<_, Vec<u8>>(0)
            })?;
        let mut values = Vec::new();
        for row in rows {
            if let Ok(id) = <[u8; 32]>::try_from(row?.as_slice()) {
                values.push(id);
            }
        }
        Ok(values)
    }

    fn ensure_capacity(&self, records: &[FlaggedFileRecord]) -> anyhow::Result<()> {
        self.ensure_capacity_with_limits(
            records,
            MAX_ACTIVE_RECORDS,
            MAX_DATABASE_BYTES,
            MIN_FREE_DISK_BYTES,
            MAX_DAILY_NEW_RECORDS,
        )
    }

    fn ensure_capacity_with_limits(
        &self,
        records: &[FlaggedFileRecord],
        max_active_records: usize,
        max_database_bytes: u64,
        min_free_disk_bytes: u64,
        max_daily_records: u64,
    ) -> anyhow::Result<()> {
        if self.path == Path::new(":memory:") {
            return Ok(());
        }
        let database_size_bytes = total_database_size(&self.path);
        let active_records = self.active_count(unix_time_ms())?;
        let available_disk_bytes = available_disk_bytes(&self.path);
        let projected_records = records.len().min(100);
        if active_records.saturating_add(projected_records) > max_active_records {
            bail!("storage safety mode: active record limit would be exceeded");
        }
        let projected_bytes = records
            .iter()
            .take(100)
            .map(|record| {
                record
                    .encode()
                    .map(|bytes| bytes.len() as u64)
                    .unwrap_or(u64::MAX)
            })
            .try_fold(0_u64, u64::checked_add)
            .context("storage projection overflow")?;
        if database_size_bytes.saturating_add(projected_bytes) > max_database_bytes {
            bail!("storage safety mode: database byte limit would be exceeded");
        }
        if available_disk_bytes < min_free_disk_bytes.saturating_add(projected_bytes) {
            bail!("storage safety mode: free disk reserve would be exceeded");
        }
        let day = unix_time_ms().div_euclid(DAY_MS);
        let today: i64 = self
            .connection
            .query_row(
                "SELECT COALESCE(record_count, 0) FROM ingestion_daily WHERE day = ?1",
                [day],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if u64::try_from(today.max(0))
            .unwrap_or(u64::MAX)
            .saturating_add(projected_records as u64)
            > max_daily_records
        {
            bail!("storage safety mode: daily growth limit would be exceeded");
        }
        Ok(())
    }

    pub fn recent_replay_seeds(
        &self,
        limit: usize,
        now_ms: i64,
    ) -> anyhow::Result<Vec<(RecordId, libp2p::PeerId, u64)>> {
        let limit = limit.min(crate::network::limits::RECENT_RECORD_CAPACITY);
        let mut statement = self.connection.prepare(
            "SELECT record_id, origin_peer_id, sequence
             FROM records WHERE expires_at > ?1
             ORDER BY created_at DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_ms, limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut seeds = Vec::with_capacity(limit);
        for row in rows {
            let (id, origin, sequence) = row?;
            let (Ok(id), Ok(origin), Ok(sequence)) = (
                <[u8; 32]>::try_from(id),
                libp2p::PeerId::from_bytes(&origin),
                u64::try_from(sequence),
            ) else {
                continue;
            };
            seeds.push((id, origin, sequence));
        }
        Ok(seeds)
    }
}

fn total_database_size(path: &Path) -> u64 {
    if path == Path::new(":memory:") {
        return 0;
    }
    let base = path.to_string_lossy();
    [
        base.to_string(),
        format!("{base}-wal"),
        format!("{base}-shm"),
    ]
    .iter()
    .filter_map(|item| std::fs::metadata(item).ok())
    .fold(0_u64, |total, metadata| {
        total.saturating_add(metadata.len())
    })
}

#[cfg(windows)]
fn available_disk_bytes(path: &Path) -> u64 {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let target = path.parent().unwrap_or(path);
    let wide: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0_u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        0
    } else {
        available
    }
}

#[cfg(not(windows))]
fn available_disk_bytes(_: &Path) -> u64 {
    u64::MAX
}

fn insert_one(tx: &Transaction<'_>, record: &FlaggedFileRecord) -> anyhow::Result<bool> {
    let encoded = record.encode().map_err(anyhow::Error::msg)?;
    let changed = tx.execute(
        "INSERT OR IGNORE INTO records (
            record_id, origin_peer_id, sequence, created_at, expires_at, sha256, blake3,
            file_size, file_name, reason, threat_level, signature, encoded_record
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            record.record_id.as_slice(),
            record.origin_peer_id.as_slice(),
            i64::try_from(record.sequence).context("sequence exceeds SQLite range")?,
            record.created_at_unix_ms,
            record.expires_at_unix_ms,
            record.sha256.as_slice(),
            record.blake3.as_slice(),
            i64::try_from(record.file_size).context("file size exceeds SQLite range")?,
            record.file_name,
            record.reason,
            record.threat_level as u8,
            record.signature,
            encoded,
        ],
    )?;
    if changed > 0 {
        tx.execute(
            "INSERT INTO origin_sequences(origin_peer_id, highest_sequence)
             VALUES (?1, ?2)
             ON CONFLICT(origin_peer_id) DO UPDATE SET
                highest_sequence = MAX(highest_sequence, excluded.highest_sequence)",
            params![
                record.origin_peer_id.as_slice(),
                i64::try_from(record.sequence).context("sequence exceeds SQLite range")?,
            ],
        )?;
    }
    Ok(changed > 0)
}

fn increment_generation(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let current = read_u64_metadata(tx, "generation")?.unwrap_or(0);
    write_u64_metadata(tx, "generation", current.saturating_add(1))
}

fn read_u64_metadata(connection: &Connection, key: &str) -> anyhow::Result<Option<u64>> {
    let bytes = connection
        .query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
            row.get::<_, Vec<u8>>(0)
        })
        .optional()?;
    Ok(bytes
        .and_then(|v| <[u8; 8]>::try_from(v).ok())
        .map(u64::from_le_bytes))
}

fn write_u64_metadata(connection: &Connection, key: &str, value: u64) -> anyhow::Result<()> {
    connection.execute(
        "INSERT INTO metadata(key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value.to_le_bytes().as_slice()],
    )?;
    Ok(())
}

fn decode_record(encoded: &[u8]) -> anyhow::Result<FlaggedFileRecord> {
    FlaggedFileRecord::decode(encoded).map_err(anyhow::Error::msg)
}

fn to_file_signature(record: FlaggedFileRecord) -> FileSignature {
    FileSignature {
        blake3_hash: hex(&record.blake3),
        file_name: record
            .file_name
            .clone()
            .unwrap_or_else(|| "unnamed file".to_owned()),
        file_size: record.file_size,
        flagged_by_peer: record
            .origin_peer_id()
            .map(|p| p.to_string())
            .unwrap_or_else(|_| "invalid peer".to_owned()),
        flagged_at: Utc
            .timestamp_millis_opt(record.created_at_unix_ms)
            .single()
            .unwrap_or_else(Utc::now),
        reason: record.reason,
        threat_level: match record.threat_level {
            ThreatLevel::Malicious => "MALICIOUS".to_owned(),
        },
    }
}

fn decode_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;

    fn record(key: &identity::Keypair, sequence: u64, created: i64) -> FlaggedFileRecord {
        FlaggedFileRecord::create(
            key,
            sequence,
            created,
            [sequence as u8; 32],
            [sequence as u8; 32],
            12,
            Some(format!("{sequence}.bin")),
        )
        .unwrap()
    }

    #[test]
    fn sqlite_is_indexed_incremental_and_duplicate_safe() {
        let db = SharedSignatureDb::in_memory().unwrap();
        let key = identity::Keypair::generate_ed25519();
        let now = unix_time_ms();
        let first = record(&key, 1, now);
        assert!(db.insert_record(&first).unwrap());
        assert!(!db.insert_record(&first).unwrap());
        assert_eq!(db.count(), 1);
        assert_eq!(db.state().unwrap().generation, 1);
        assert!(db.is_flagged(&hex(&first.blake3)).is_some());
    }

    #[test]
    fn inventory_and_record_requests_are_bucketed_and_bounded() {
        let db = SharedSignatureDb::in_memory().unwrap();
        let key = identity::Keypair::generate_ed25519();
        let now = unix_time_ms();
        for sequence in 1..=300 {
            db.insert_record(&record(&key, sequence, now)).unwrap();
        }
        let inventory = db.inventory(now).unwrap();
        assert_eq!(inventory.record_count, 300);
        let bucket = inventory.bucket_digests[0].start_unix;
        let (ids, next) = db.record_ids(bucket, None, 100, now).unwrap();
        assert_eq!(ids.len(), 100);
        assert!(next.is_some());
        assert_eq!(db.records_by_ids(&ids).unwrap().len(), 100);
    }

    #[test]
    fn sequence_is_monotonic_and_identity_state_can_be_cleared() {
        let db = SharedSignatureDb::in_memory().unwrap();
        let peer = libp2p::PeerId::random();
        assert_eq!(db.next_local_sequence(&peer).unwrap(), 1);
        assert_eq!(db.next_local_sequence(&peer).unwrap(), 2);
        db.clear_identity_state().unwrap();
        assert_eq!(db.next_local_sequence(&peer).unwrap(), 1);
    }

    #[test]
    fn active_records_seed_replay_state_after_restart() {
        let db = SharedSignatureDb::in_memory().unwrap();
        let key = identity::Keypair::generate_ed25519();
        let now = unix_time_ms();
        let record = record(&key, 1, now);
        db.insert_record(&record).unwrap();
        let seeds = db.recent_replay_seeds(10, now).unwrap();
        assert_eq!(seeds.len(), 1);
        assert_eq!(seeds[0].0, record.record_id);
        assert_eq!(seeds[0].2, record.sequence);
    }

    #[test]
    fn storage_limits_reject_record_count_bytes_low_disk_and_daily_growth() {
        let root = tempfile::tempdir().unwrap();
        let database = SignatureDatabase::open(root.path().join("limits.db")).unwrap();
        let key = identity::Keypair::generate_ed25519();
        let item = record(&key, 1, unix_time_ms());
        let large = usize::MAX;
        assert!(database
            .ensure_capacity_with_limits(std::slice::from_ref(&item), 0, u64::MAX, 0, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("active record"));
        assert!(database
            .ensure_capacity_with_limits(std::slice::from_ref(&item), large, 0, 0, u64::MAX)
            .unwrap_err()
            .to_string()
            .contains("database byte"));
        assert!(database
            .ensure_capacity_with_limits(
                std::slice::from_ref(&item),
                large,
                u64::MAX,
                u64::MAX,
                u64::MAX,
            )
            .unwrap_err()
            .to_string()
            .contains("free disk"));
        assert!(database
            .ensure_capacity_with_limits(&[item], large, u64::MAX, 0, 0)
            .unwrap_err()
            .to_string()
            .contains("daily growth"));
    }

    #[test]
    fn database_size_includes_wal_and_shared_memory_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("size.db");
        std::fs::write(&path, [0; 3]).unwrap();
        std::fs::write(format!("{}-wal", path.display()), [0; 5]).unwrap();
        std::fs::write(format!("{}-shm", path.display()), [0; 7]).unwrap();
        assert_eq!(total_database_size(&path), 15);
    }
}
