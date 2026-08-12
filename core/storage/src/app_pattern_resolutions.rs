//! `app_pattern_resolutions` persistence.
//!
//! Last-good exe-path resolutions keyed by the app pattern (name or glob), e.g.
//! `openvpn*` → `C:\Tools\openvpn.exe`. Lives in the STATE DB (not the
//! rebuildable cache DB) because an exe path is machine-wide — NOT per-SID — and
//! must survive the cache-rebuild reset.
//!
//! The in-memory `AppPathResolver` only sees an exe that is currently running,
//! registered under `App Paths`, or reachable by a bounded Program-Files walk; a
//! VPN client that is installed off the beaten path and not currently running
//! resolves to nothing, so its kill-switch ALE_APP_ID exemption never installs.
//! Persisting the last-good resolution lets the `PersistentAppPathResolver`
//! decorator (service-runtime) fall back to it after a restart.
//!
//! # Row-set replace semantics
//!
//! [`AppPatternResolutionsRepository::upsert`] replaces the whole row set for a
//! pattern (delete-then-insert) so a pattern's persisted paths always mirror the
//! most recent successful resolution — a since-uninstalled binary does not linger.
//! At most [`MAX_PATHS_PER_PATTERN`] paths are kept per pattern (a glob can match
//! a family; the cap bounds the row count).

use rusqlite::{params, Connection};

use crate::error::{StorageError, StorageResult};

/// Cap on persisted paths per pattern. A glob may match several installs; a small
/// cap keeps a pathological pattern from bloating the table while covering the
/// realistic 32/64-bit + per-user/per-machine spread.
pub const MAX_PATHS_PER_PATTERN: usize = 4;

/// Repository over the `app_pattern_resolutions` table (state DB).
pub struct AppPatternResolutionsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> AppPatternResolutionsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Replace the persisted path set for `pattern` with `paths` (deduped,
    /// capped at [`MAX_PATHS_PER_PATTERN`]), stamping `now` (UTC Unix millis) as
    /// the resolution time. Delete-then-insert inside one transaction so a reader
    /// never observes a mixed old/new set. An empty `paths` clears the pattern.
    pub fn upsert(&self, pattern: &str, paths: &[String], now: i64) -> StorageResult<()> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions tx: {e}")))?;
        tx.execute(
            "DELETE FROM app_pattern_resolutions WHERE pattern = ?1",
            params![pattern],
        )
        .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions delete: {e}")))?;

        // Dedup (case-insensitive) while preserving order, then cap.
        let mut seen = std::collections::HashSet::new();
        for path in paths
            .iter()
            .filter(|p| !p.is_empty())
            .filter(|p| seen.insert(p.to_ascii_lowercase()))
            .take(MAX_PATHS_PER_PATTERN)
        {
            tx.execute(
                "INSERT OR REPLACE INTO app_pattern_resolutions
                 (pattern, resolved_path, resolved_at)
                 VALUES (?1, ?2, ?3)",
                params![pattern, path, now],
            )
            .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions insert: {e}")))?;
        }
        tx.commit()
            .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions commit: {e}")))?;
        Ok(())
    }

    /// Load the persisted resolved paths for `pattern`, newest-resolution first
    /// then by path for a stable order. Empty when the pattern was never resolved.
    pub fn load(&self, pattern: &str) -> StorageResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT resolved_path FROM app_pattern_resolutions
                 WHERE pattern = ?1
                 ORDER BY resolved_at DESC, resolved_path ASC",
            )
            .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions prepare: {e}")))?;
        let rows = stmt
            .query_map(params![pattern], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Internal(format!("app_pattern_resolutions query: {e}")))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| {
                StorageError::Internal(format!("app_pattern_resolutions row: {e}"))
            })?);
        }
        Ok(out)
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
    fn upsert_then_load_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        repo.upsert("openvpn*", &[r"C:\Tools\openvpn.exe".to_string()], 100)
            .expect("upsert");
        assert_eq!(
            repo.load("openvpn*").expect("load"),
            vec![r"C:\Tools\openvpn.exe".to_string()]
        );
    }

    #[test]
    fn load_unknown_pattern_is_empty() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        assert!(repo.load("never-seen*").expect("load").is_empty());
    }

    #[test]
    fn upsert_replaces_prior_row_set() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        repo.upsert(
            "vpn*",
            &[r"C:\A\old.exe".to_string(), r"C:\B\old2.exe".to_string()],
            100,
        )
        .expect("first upsert");
        // A new resolution supersedes the whole set — the old paths are gone.
        repo.upsert("vpn*", &[r"C:\C\new.exe".to_string()], 200)
            .expect("second upsert");
        assert_eq!(
            repo.load("vpn*").expect("load"),
            vec![r"C:\C\new.exe".to_string()]
        );
    }

    #[test]
    fn upsert_caps_paths_per_pattern() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        let many: Vec<String> = (0..10).map(|i| format!(r"C:\P\app{i}.exe")).collect();
        repo.upsert("many*", &many, 100).expect("upsert");
        assert_eq!(
            repo.load("many*").expect("load").len(),
            MAX_PATHS_PER_PATTERN,
            "at most MAX_PATHS_PER_PATTERN paths persist",
        );
    }

    #[test]
    fn upsert_dedups_case_insensitively() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        repo.upsert(
            "d*",
            &[
                r"C:\X\a.exe".to_string(),
                r"c:\x\A.EXE".to_string(), // case-insensitive dup
            ],
            100,
        )
        .expect("upsert");
        assert_eq!(repo.load("d*").expect("load").len(), 1);
    }

    #[test]
    fn upsert_empty_paths_clears_pattern() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = AppPatternResolutionsRepository::new(&conn);
        repo.upsert("c*", &[r"C:\X\a.exe".to_string()], 100)
            .expect("seed");
        repo.upsert("c*", &[], 200).expect("clear");
        assert!(repo.load("c*").expect("load").is_empty());
    }
}
