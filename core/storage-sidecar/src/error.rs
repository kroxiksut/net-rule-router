//! Error types for the sidecar database.
//!
//! Failures here are non-fatal from the user's perspective — comments
//! and passthrough sections are decoration, not routing state. The GUI
//! surfaces a status-line warning and proceeds with reduced fidelity
//! (e.g. comments missing on this session, passthrough lost on next
//! export). The bridge translates `SidecarError` to a status string;
//! it does not propagate failures into mutation flows.

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

    /// The requested path could not be resolved — no `%APPDATA%` (on
    /// Windows) and no override via the `NRR_SIDECAR_PATH` env var.
    #[error("could not resolve sidecar database path: {reason}")]
    PathResolution { reason: String },
}

/// Convenience alias for sidecar fallible operations.
pub type SidecarResult<T> = Result<T, SidecarError>;
