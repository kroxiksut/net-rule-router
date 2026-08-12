use std::fmt;

/// All errors that can be produced by the storage layer.
///
/// `Internal` acts as a catch-all for backend errors (SQLite I/O, constraint
/// violations, etc.) without leaking the rusqlite type into the public API.
/// The SQLite implementation converts `rusqlite::Error` into this
/// variant via its `From` impl.
#[derive(Debug)]
pub enum StorageError {
    /// Database file or directory is inaccessible (missing, permissions, locked
    /// by another process at startup).
    StorageUnavailable(String),
    /// Schema migration failed between two specific versions.
    MigrationFailed {
        from_version: u32,
        to_version: u32,
        reason: String,
    },
    /// A content integrity check failed.
    IntegrityFailed(IntegrityFailureKind),
    /// The FQDN/IP cache database is corrupt and needs to be rebuilt.
    CorruptCache(String),
    /// The database schema version is newer than this build supports (opened by
    /// a newer binary, then downgraded).  Must not attempt to downgrade.
    UnsupportedSchemaVersion { found: u32, max_supported: u32 },
    /// SQLite `SQLITE_BUSY` — another writer held the lock longer than
    /// `PRAGMA busy_timeout`.
    BusyTimeout { timeout_ms: u32 },
    /// Backend error that does not fit a more specific variant.  Message
    /// carries the stringified rusqlite / I/O error without exposing the type.
    Internal(String),
}

/// Discriminates which layer of integrity failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IntegrityFailureKind {
    /// `nrr_fqdn_ip_cache.db` failed SQLite integrity_check.
    CacheCorrupt,
    /// `nrr_service_state.db` active revision pointer / LKG pointer is corrupt.
    PolicyRevisionCorrupt,
    /// SHA-256 content hash stored in metadata does not match recomputed hash.
    HashMismatch,
    /// Last-known-good revision pointer is missing — cannot fall back safely.
    MissingLastKnownGood,
}

/// Alias for `Result<T, StorageError>` — the standard return type for all
/// storage layer operations.
pub type StorageResult<T> = Result<T, StorageError>;

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageUnavailable(msg) => write!(f, "storage unavailable: {msg}"),
            Self::MigrationFailed {
                from_version,
                to_version,
                reason,
            } => {
                write!(
                    f,
                    "migration v{from_version}→v{to_version} failed: {reason}"
                )
            }
            Self::IntegrityFailed(kind) => write!(f, "integrity check failed: {kind:?}"),
            Self::CorruptCache(msg) => write!(f, "cache corrupt: {msg}"),
            Self::UnsupportedSchemaVersion {
                found,
                max_supported,
            } => {
                write!(
                    f,
                    "unsupported schema version {found} (max supported: {max_supported})"
                )
            }
            Self::BusyTimeout { timeout_ms } => {
                write!(f, "database busy timeout after {timeout_ms} ms")
            }
            Self::Internal(msg) => write!(f, "internal storage error: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}
