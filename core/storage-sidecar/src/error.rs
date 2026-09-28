//! Error types for the sidecar database.
//!
//! Failures here are non-fatal for the user — comments and passthrough are
//! decoration, not routing state. The launcher answers a failed `sidecar.*`
//! request with a `sidecar-error` RPC error and QML degrades (no comments this
//! session, passthrough missing from the next export); nothing propagates into
//! mutation flows.

use thiserror::Error;

/// Errors that can occur while operating on the sidecar database.
#[derive(Debug, Error)]
pub enum SidecarError {
    /// SQLite-level failure (open, prepare, execute, row decode).
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// I/O failure during path resolution or directory creation.
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    /// The on-disk schema version is newer than this binary knows how
    /// to handle. Refusing to open avoids silently downgrading data
    /// the user persisted with a future build.
    #[error("sidecar schema version {found} is newer than supported {supported}")]
    SchemaTooNew { found: u32, supported: u32 },

    /// The migration runner aborted because checksum verification of a
    /// stored migration step failed. Indicates the database was edited
    /// outside our tooling between sessions.
    #[error("sidecar schema migration corrupted: {detail}")]
    MigrationCorrupted { detail: String },

    /// No usable path: no per-user data directory (`%LOCALAPPDATA%` on
    /// Windows, `$XDG_DATA_HOME`/`$HOME` elsewhere), or an unusable
    /// `NRR_SIDECAR_PATH` override.
    #[error("could not resolve sidecar database path: {reason}")]
    PathResolution { reason: String },

    /// The file opened, but the filesystem under it cannot give the database
    /// what it needs (e.g. WAL on a network share).
    #[error("sidecar database environment unsupported: {reason}")]
    Environment { reason: String },

    /// A request or a value to store is malformed — a missing field, a wrong
    /// type, an empty content hash.
    #[error("invalid sidecar request: {reason}")]
    InvalidPayload { reason: String },

    /// The `sidecar.*` operation name is not one this build serves.
    #[error("unsupported sidecar operation: {operation}")]
    UnsupportedOperation { operation: String },
}

/// Convenience alias for sidecar fallible operations.
pub type SidecarResult<T> = Result<T, SidecarError>;
