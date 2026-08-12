//! `routing_pause_state` repository (per-SID).
//!
//! Persistent per-user pause flag. Default after install is "not paused"
//! (absent row). User clicks "Disable rules" in GUI/tray → row written
//! with `paused = 1`. State persists across reboots, so a pause survives
//! a service restart rather than silently re-enabling routing.
//!
//! Reads are open (any caller can check pause state for their own SID);
//! writes go through the `RoutingPauseToggle` IPC handler with
//! `IpcOperationClass::UserScopedConfiguration`.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── DTO ───────────────────────────────────────────────────────────────────────

/// Per-SID pause state row. Absent row ≡ not paused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingPauseRecord {
    pub sid: String,
    pub paused: bool,
    /// Wall-clock seconds at the moment the SID entered the paused state.
    /// `None` when `paused == false` or when the row was inserted with
    /// `paused = false` to clear an earlier pause.
    pub paused_at: Option<i64>,
    /// Optional free-text reason supplied by the user (kept short by the
    /// IPC handler). May be `None`.
    pub pause_reason: Option<String>,
    pub updated_at: i64,
}

// ── Repository ────────────────────────────────────────────────────────────────

pub struct RoutingPauseStateRepository<'c> {
    conn: &'c Connection,
}

impl<'c> RoutingPauseStateRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the pause record for `sid`, or `None` if no row exists.
    pub fn get(&self, sid: &str) -> StorageResult<Option<RoutingPauseRecord>> {
        if sid.is_empty() {
            return Err(StorageError::Internal("get: empty sid".into()));
        }
        self.conn
            .query_row(
                "SELECT sid, paused, paused_at, pause_reason, updated_at
                 FROM routing_pause_state WHERE sid = ?1",
                params![sid],
                |row| {
                    let paused_int: i64 = row.get(1)?;
                    Ok(RoutingPauseRecord {
                        sid: row.get(0)?,
                        paused: paused_int != 0,
                        paused_at: row.get(2)?,
                        pause_reason: row.get(3)?,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("routing_pause_state get: {e}")))
    }

    /// Convenience read — returns `false` for absent rows.
    pub fn is_paused(&self, sid: &str) -> StorageResult<bool> {
        Ok(self.get(sid)?.map(|r| r.paused).unwrap_or(false))
    }

    /// Sets pause state for `sid`. Inserts or replaces the row.
    /// `paused_at` is set to `now` when `paused == true`, cleared to
    /// `NULL` when `paused == false` (so the audit timeline is clean).
    pub fn set_paused(
        &self,
        sid: &str,
        paused: bool,
        reason: Option<&str>,
        now: i64,
    ) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal("set_paused: empty sid".into()));
        }
        let paused_at = if paused { Some(now) } else { None };
        let reason = if paused { reason } else { None };
        self.conn
            .execute(
                "INSERT INTO routing_pause_state
                 (sid, paused, paused_at, pause_reason, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sid) DO UPDATE SET
                     paused = excluded.paused,
                     paused_at = excluded.paused_at,
                     pause_reason = excluded.pause_reason,
                     updated_at = excluded.updated_at",
                params![sid, paused as i64, paused_at, reason, now],
            )
            .map_err(|e| StorageError::Internal(format!("routing_pause_state set: {e}")))?;
        Ok(())
    }

    /// Returns all SIDs that are currently paused. Used on startup to
    /// skip the recompile step for paused users.
    pub fn list_paused(&self) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT sid FROM routing_pause_state WHERE paused = 1 ORDER BY sid")
            .map_err(|e| StorageError::Internal(format!("routing_pause_state list prep: {e}")))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("routing_pause_state list: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| StorageError::Internal(format!("row: {e}")))?);
        }
        Ok(out)
    }

    /// Removes the row for `sid`. Idempotent — absent rows succeed
    /// silently. The repository keeps history rows when toggling
    /// pause off (`set_paused(false)`); use this only for explicit
    /// cleanup (e.g. user uninstall, account removal).
    pub fn forget(&self, sid: &str) -> StorageResult<()> {
        if sid.is_empty() {
            return Err(StorageError::Internal("forget: empty sid".into()));
        }
        self.conn
            .execute(
                "DELETE FROM routing_pause_state WHERE sid = ?1",
                params![sid],
            )
            .map_err(|e| StorageError::Internal(format!("routing_pause_state forget: {e}")))?;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::{open_connection, SqliteMigrationRunner};
    use crate::repository::MigrationRunner;

    fn open_state_db(dir: &tempfile::TempDir) -> Connection {
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    #[test]
    fn absent_row_is_not_paused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        assert!(!repo.is_paused("S-1-5-21-A").expect("query"));
        assert!(repo.get("S-1-5-21-A").expect("query").is_none());
    }

    #[test]
    fn set_paused_creates_row_with_paused_at() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        repo.set_paused("S-1-A", true, Some("travel"), 1_700_000_000)
            .expect("set");
        let r = repo.get("S-1-A").expect("get").expect("present");
        assert!(r.paused);
        assert_eq!(r.paused_at, Some(1_700_000_000));
        assert_eq!(r.pause_reason, Some("travel".to_string()));
        assert_eq!(r.updated_at, 1_700_000_000);
    }

    #[test]
    fn unpause_clears_paused_at_and_reason() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        repo.set_paused("S-1-A", true, Some("travel"), 100)
            .expect("pause");
        repo.set_paused("S-1-A", false, None, 200).expect("unpause");
        let r = repo.get("S-1-A").expect("get").expect("present");
        assert!(!r.paused);
        assert!(r.paused_at.is_none());
        assert!(r.pause_reason.is_none());
        assert_eq!(r.updated_at, 200);
    }

    #[test]
    fn pause_state_is_per_sid_independent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        repo.set_paused("S-A", true, None, 100).expect("a");
        repo.set_paused("S-B", false, None, 100).expect("b");
        assert!(repo.is_paused("S-A").expect("a"));
        assert!(!repo.is_paused("S-B").expect("b"));
    }

    #[test]
    fn list_paused_returns_only_paused_sids_sorted() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        repo.set_paused("S-Z", true, None, 0).expect("z");
        repo.set_paused("S-A", true, None, 0).expect("a");
        repo.set_paused("S-M", false, None, 0).expect("m");
        let list = repo.list_paused().expect("list");
        assert_eq!(list, vec!["S-A".to_string(), "S-Z".to_string()]);
    }

    #[test]
    fn forget_is_idempotent_on_unknown_sid() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        repo.forget("ghost").expect("forget");
    }

    #[test]
    fn empty_sid_rejected() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RoutingPauseStateRepository::new(&conn);
        assert!(repo.get("").is_err());
        assert!(repo.set_paused("", true, None, 0).is_err());
        assert!(repo.forget("").is_err());
    }

    #[test]
    fn pause_state_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("temp dir");
        {
            let conn = open_state_db(&dir);
            let repo = RoutingPauseStateRepository::new(&conn);
            repo.set_paused("S-Persist", true, Some("offline"), 999)
                .expect("set");
        }
        let path = dir.path().join("state.db");
        let conn = open_connection(&path).expect("reopen");
        let repo = RoutingPauseStateRepository::new(&conn);
        let r = repo.get("S-Persist").expect("get").expect("present");
        assert!(r.paused);
        assert_eq!(r.pause_reason, Some("offline".to_string()));
    }
}
