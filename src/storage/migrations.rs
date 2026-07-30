pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

CREATE TABLE IF NOT EXISTS records (
    record_id BLOB PRIMARY KEY CHECK(length(record_id) = 32),
    origin_peer_id BLOB NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence >= 0),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    sha256 BLOB NOT NULL CHECK(length(sha256) = 32),
    blake3 BLOB NOT NULL CHECK(length(blake3) = 32),
    file_size INTEGER NOT NULL CHECK(file_size >= 0),
    file_name TEXT,
    reason TEXT NOT NULL,
    threat_level INTEGER NOT NULL,
    signature BLOB NOT NULL,
    encoded_record BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS records_origin_sequence
ON records(origin_peer_id, sequence);
CREATE INDEX IF NOT EXISTS records_created_at ON records(created_at);
CREATE INDEX IF NOT EXISTS records_expires_at ON records(expires_at);
CREATE INDEX IF NOT EXISTS records_sha256 ON records(sha256);
CREATE INDEX IF NOT EXISTS records_blake3 ON records(blake3);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
INSERT OR IGNORE INTO metadata(key, value) VALUES ('generation', x'0000000000000000');

CREATE TABLE IF NOT EXISTS origin_sequences (
    origin_peer_id BLOB PRIMARY KEY,
    highest_sequence INTEGER NOT NULL CHECK(highest_sequence >= 0)
);
"#;
