//! Sidecar database handle.
//!
//! Owns the single `rusqlite::Connection` for the sidecar SQLite file,
//! configured with WAL journal mode and a 5000 ms busy timeout per the
//! convention from `nrr-storage`. The migration runner is invoked
//! automatically on [`SidecarDb::open`]; DAO methods land on this type
//! in +0.3..+0.5 and dispatch through the inner `RefCell<Connection>`
//! so they can take `&self` (one connection, one thread, mirroring
//! `nrr-storage::store`).

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::Connection;

use crate::error::{SidecarError, SidecarResult};
use crate::migration::{self, MigrationSummary};

/// Owns the sidecar SQLite connection.
pub struct SidecarDb {
    /// Resolved on-disk path, kept for diagnostics and log messages.
    path: PathBuf,
    /// The owning connection. `RefCell` so DAO methods that take
    /// `&self` can still call `transaction()` (which needs `&mut`).
    conn: RefCell<Connection>,
    /// Outcome of the migration run that happened during `open`.
    /// Exposed for diagnostics; not load-bearing at runtime.
    last_migration: MigrationSummary,
}

impl SidecarDb {
    /// Open the sidecar database at `path`, applying any pending
    /// schema migrations.
    ///
    /// The parent directory is expected to exist; callers obtain
    /// `path` through [`crate::profile::resolve_path`] which takes
    /// care of that.
    ///
    /// On success the connection has:
    ///
    /// * `journal_mode = WAL` (verified — some network filesystems
    ///   silently fall back to `delete`, which we treat as a fatal
    ///   environment error).
    /// * `busy_timeout = 5000 ms` (matches `nrr-storage`; absorbs
    ///   contention bursts during concurrent reads from the QML
    ///   side without surfacing `SQLITE_BUSY` to the bridge).
    /// * Schema at [`crate::LATEST_SCHEMA_VERSION`].
    pub fn open(path: impl AsRef<Path>) -> SidecarResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        configure_pragmas(&conn, &path)?;
        let last_migration = migration::migrate(&mut conn)?;
        let db = Self {
            path,
            conn: RefCell::new(conn),
            last_migration,
        };
        // Startup VACUUM is throttled by file size AND minimum
        // interval — see `vacuum::maybe_vacuum`. Failures are
        // intentionally non-fatal: if VACUUM can't run for any
        // reason the DB is still functional and the next launch will
        // try again. Logging is left to the caller (the launcher
        // process will see the error if it surfaces, but we don't
        // want a transient stat() failure to block GUI startup).
        let _ = db.maybe_vacuum();
        Ok(db)
    }

    /// Open the sidecar at the default per-user location, honouring
    /// the `NRR_SIDECAR_PATH` env override.
    ///
    /// Production entrypoint used by the launcher; tests typically
    /// call [`SidecarDb::open`] with an explicit tempfile path
    /// instead so they don't depend on the host's user profile.
    pub fn open_default() -> SidecarResult<Self> {
        let path = crate::profile::resolve_path()?;
        Self::open(path)
    }

    /// Resolved on-disk path for diagnostics. Not used by DAO code.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Outcome of the last (i.e. open-time) migration run.
    pub fn last_migration(&self) -> &MigrationSummary {
        &self.last_migration
    }

    /// Full-reset support. Clears every user
    /// data row (rule comments, foreign-OS passthrough sections, parked
    /// pending-apply snapshot, cached external IPs) in one transaction,
    /// leaving the schema and migration state intact so the database
    /// returns to its just-created (post-install) shape. Driven by the
    /// GUI "Full reset" action via the `sidecar.reset` RPC.
    pub fn reset_all(&self) -> SidecarResult<()> {
        let mut conn = self.conn_mut();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM rule_metadata", [])?;
        tx.execute("DELETE FROM passthrough", [])?;
        tx.execute("DELETE FROM pending_apply", [])?;
        tx.execute("DELETE FROM external_ip_cache", [])?;
        tx.commit()?;
        Ok(())
    }

    /// Internal accessor used by DAO modules in +0.3..+0.5.
    #[allow(dead_code)] // wired in +0.3 onwards
    pub(crate) fn conn(&self) -> std::cell::Ref<'_, Connection> {
        self.conn.borrow()
    }

    /// Internal `&mut` accessor for DAO methods that open transactions.
    #[allow(dead_code)] // wired in +0.3 onwards
    pub(crate) fn conn_mut(&self) -> std::cell::RefMut<'_, Connection> {
        self.conn.borrow_mut()
    }
}

/// Apply the baseline PRAGMAs we depend on. WAL mode is mandatory and
/// the value is read back to guard against silent filesystem-level
/// downgrades.
fn configure_pragmas(conn: &Connection, path: &Path) -> SidecarResult<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
    if mode != "wal" {
        return Err(SidecarError::PathResolution {
            reason: format!(
                "WAL mode not supported at {} (returned journal_mode = {mode:?})",
                path.display()
            ),
        });
    }
    conn.busy_timeout(Duration::from_millis(5_000))?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LATEST_SCHEMA_VERSION;

    #[test]
    fn open_creates_schema_at_latest_version() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let db = SidecarDb::open(&path)?;
        assert_eq!(db.path(), path.as_path());
        assert_eq!(db.last_migration().to_version, LATEST_SCHEMA_VERSION);
        assert_eq!(db.last_migration().from_version, 0);
        Ok(())
    }

    #[test]
    fn reopen_is_noop() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let _db1 = SidecarDb::open(&path)?;
        let db2 = SidecarDb::open(&path)?;
        assert_eq!(db2.last_migration().from_version, LATEST_SCHEMA_VERSION);
        assert_eq!(db2.last_migration().to_version, LATEST_SCHEMA_VERSION);
        assert!(db2.last_migration().migrations_applied.is_empty());
        Ok(())
    }

    #[test]
    fn open_sets_wal_journal_mode() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let db = SidecarDb::open(&path)?;
        let mode: String = db
            .conn()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
        assert_eq!(mode, "wal");
        Ok(())
    }
}
