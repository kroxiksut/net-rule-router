//! Sidecar database handle.
//!
//! One `rusqlite::Connection` per PROCESS: the GUI launcher and the tray
//! launcher each open the same per-user file, so every rule here — WAL, the
//! 5000 ms busy timeout, the migration's write lock, the non-blocking
//! checkpoint, the replaced-file check — assumes a second live connection.
//! DAO methods take `&self` and borrow the connection through a `RefCell`
//! (one connection, one thread, like `nrr-storage::store`).

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode};

use crate::error::{SidecarError, SidecarResult};
use crate::migration::{self, MigrationSummary};

/// How long a statement waits for the other process's lock before failing.
pub(crate) const BUSY_TIMEOUT: Duration = Duration::from_millis(5_000);

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
    /// Which file `path` named when the connection opened it.
    identity: Option<FileIdentity>,
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
    /// * `busy_timeout = 5000 ms`, so the other process's short writes
    ///   never surface as `SQLITE_BUSY`.
    /// * Schema at [`crate::LATEST_SCHEMA_VERSION`].
    pub fn open(path: impl AsRef<Path>) -> SidecarResult<Self> {
        let path = path.as_ref().to_path_buf();
        let mut conn = Connection::open(&path)?;
        restrict_db_to_owner(&path);
        configure_pragmas(&conn, &path)?;
        let last_migration = migration::migrate(&mut conn)?;
        let identity = file_identity(&path);
        let db = Self {
            path,
            conn: RefCell::new(conn),
            last_migration,
            identity,
        };
        // Throttled by size and interval (`vacuum::maybe_vacuum`). A failure
        // leaves a working database and the next launch tries again, so it must
        // not block startup.
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

    /// Whether [`path`](Self::path) no longer names the file this connection
    /// has open.
    ///
    /// On Unix the other process can unlink and recreate the file under a live
    /// connection (the GUI's reset of an unopenable sidecar, a purge script),
    /// and this connection would keep serving the orphaned inode until the
    /// process restarts. Windows refuses to delete an open database, so there
    /// only a missing file counts. A holder that sees `true` reopens the path.
    pub fn file_replaced(&self) -> bool {
        file_identity(&self.path) != self.identity
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

    /// Shared borrow of the connection for DAO reads.
    pub(crate) fn conn(&self) -> std::cell::Ref<'_, Connection> {
        self.conn.borrow()
    }

    /// Exclusive borrow for DAO methods that open transactions.
    pub(crate) fn conn_mut(&self) -> std::cell::RefMut<'_, Connection> {
        self.conn.borrow_mut()
    }
}

/// What makes two opens of one path the same file: device and inode on Unix.
/// Elsewhere an open database cannot be replaced, so existence is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

fn file_identity(path: &Path) -> Option<FileIdentity> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(FileIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        Some(FileIdentity {
            device: 0,
            inode: 0,
        })
    }
}

/// Keep the sidecar file to its owner on Unix — the same reason as the
/// directory (see `profile::restrict_to_owner`): it holds the user's own
/// comments and parked edits, and the default `0644` hands them to every local
/// account. Applied on every open rather than on create only, so a file that
/// predates this (or arrived with a roaming profile) is tightened too.
///
/// Best-effort: a share that cannot express the mode must not stop the sidecar
/// from opening.
fn restrict_db_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Apply the baseline PRAGMAs we depend on. WAL mode is mandatory and
/// the value is read back to guard against silent filesystem-level
/// downgrades.
fn configure_pragmas(conn: &Connection, path: &Path) -> SidecarResult<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    let mode = enable_wal(conn)?;
    if mode != "wal" {
        return Err(SidecarError::Environment {
            reason: format!(
                "WAL mode not supported at {} (returned journal_mode = {mode:?})",
                path.display()
            ),
        });
    }
    // Same as the service store, so the schema's foreign keys mean the same
    // thing in both databases.
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(())
}

/// Switch to WAL, retrying on `SQLITE_BUSY` within [`BUSY_TIMEOUT`].
///
/// Converting a fresh file needs an exclusive lock and SQLite answers BUSY
/// without consulting the busy handler — so when the GUI and the tray open a
/// new sidecar in the same instant, the loser failed outright.
fn enable_wal(conn: &Connection) -> SidecarResult<String> {
    let deadline = Instant::now() + BUSY_TIMEOUT;
    loop {
        match conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get::<_, String>(0)) {
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == ErrorCode::DatabaseBusy && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            other => return Ok(other?),
        }
    }
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

    /// The sidecar holds the user's own rule comments and parked edits. Created
    /// with the default mask it lands at `0644`, so on a shared Linux box every
    /// local account could read another user's notes.
    #[cfg(unix)]
    #[test]
    fn the_database_is_readable_only_by_its_owner() -> SidecarResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let _db = SidecarDb::open(&path)?;
        let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "group and other must have nothing");
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

    /// GUI and tray start together on a fresh install and open the same file
    /// in the same instant. Reading the version outside the migration's write
    /// lock let both see 0, and the loser re-ran the v1 DDL.
    #[test]
    fn two_processes_opening_a_fresh_file_together_both_succeed() -> SidecarResult<()> {
        use std::sync::{Arc, Barrier};
        for round in 0..50 {
            let tmp = tempfile::tempdir()?;
            let path = tmp.path().join("sidecar.db");
            let barrier = Arc::new(Barrier::new(2));
            let openers: Vec<_> = (0..2)
                .map(|_| {
                    let path = path.clone();
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        SidecarDb::open(&path)
                            .map(|_| ())
                            .map_err(|e| e.to_string())
                    })
                })
                .collect();
            for opener in openers {
                let outcome = opener
                    .join()
                    .unwrap_or_else(|_| Err("opener thread panicked".to_string()));
                assert_eq!(outcome, Ok(()), "round {round}");
            }
        }
        Ok(())
    }

    /// Unix lets the GUI unlink and rebuild the file while the tray's connection
    /// still holds the old inode; the tray has to be able to tell.
    #[cfg(unix)]
    #[test]
    fn a_file_recreated_under_a_live_connection_is_noticed() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let tray = SidecarDb::open(&path)?;
        assert!(!tray.file_replaced());

        for suffix in ["", "-wal", "-shm"] {
            let mut victim = path.clone().into_os_string();
            victim.push(suffix);
            match std::fs::remove_file(PathBuf::from(victim)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        let gui = SidecarDb::open(&path)?;

        assert!(tray.file_replaced(), "the tray still serves the orphan");
        assert!(!gui.file_replaced());
        Ok(())
    }

    #[test]
    fn an_untouched_file_is_not_reported_replaced() -> SidecarResult<()> {
        let tmp = tempfile::tempdir()?;
        let path = tmp.path().join("sidecar.db");
        let first = SidecarDb::open(&path)?;
        let second = SidecarDb::open(&path)?;
        assert!(!first.file_replaced());
        assert!(!second.file_replaced());
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
