//! `apply_failure_policy_settings` singleton.
//!
//! Persists the global `ApplyFailurePolicy` chosen by the administrator.
//! The slug values match `nrr_service_runtime::ApplyFailurePolicy::as_slug`
//! so the storage layer and the activation coordinator stay in sync
//! without a domain dep.
//!
//! Setting requires elevation (the IPC handler marks `ApplyFailurePolicySet`
//! as `MutationStrong`); read is open to all authenticated callers via the
//! regular snapshot pipeline.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── DTO ───────────────────────────────────────────────────────────────────────

/// Persisted apply-failure-policy record.
///
/// `policy` is the raw slug as stored in SQLite (`'all-or-nothing' |
/// 'best-effort' | 'pre-flight-then-all-or-nothing'`). The activation
/// coordinator is the source of truth for the typed enum and converts
/// from/to this slug at runtime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyFailurePolicyRecord {
    pub policy: String,
    /// SID of the admin who last touched the setting. `None` for the
    /// implicit default row written on first install.
    pub set_by_sid: Option<String>,
    pub set_at: i64,
}

/// Default slug used when no row exists in the table.
///
/// `best-effort`: a single un-materializable rule (absent app, glob app
/// pattern, host that doesn't resolve yet, missing adapter) is skipped with
/// a diagnostic instead of rolling back the whole revision. Shared/preset
/// rule books always contain rules that can't materialize on a given host,
/// so all-or-nothing as the out-of-box default left users with NO active
/// policy. Admins who want exact-or-nothing can switch in Settings.
pub const DEFAULT_POLICY_SLUG: &str = "best-effort";

/// Slug allow-list — keep in sync with `ApplyFailurePolicy::as_slug`.
pub const VALID_POLICY_SLUGS: [&str; 3] = [
    "all-or-nothing",
    "best-effort",
    "pre-flight-then-all-or-nothing",
];

// ── Repository ────────────────────────────────────────────────────────────────

pub struct ApplyFailurePolicySettingsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> ApplyFailurePolicySettingsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row. Returns the implicit
    /// `all-or-nothing` default with `set_by_sid = None` and `set_at = 0`
    /// when no row has been written.
    pub fn get_or_default(&self) -> StorageResult<ApplyFailurePolicyRecord> {
        let row = self
            .conn
            .query_row(
                "SELECT policy, set_by_sid, set_at
                 FROM apply_failure_policy_settings WHERE id = 1",
                [],
                |row| {
                    Ok(ApplyFailurePolicyRecord {
                        policy: row.get(0)?,
                        set_by_sid: row.get(1)?,
                        set_at: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|e| {
                StorageError::Internal(format!("apply_failure_policy_settings get: {e}"))
            })?;
        Ok(row.unwrap_or_else(|| ApplyFailurePolicyRecord {
            policy: DEFAULT_POLICY_SLUG.to_string(),
            set_by_sid: None,
            set_at: 0,
        }))
    }

    /// Inserts or replaces the singleton row. Rejects unknown slugs
    /// before going to SQL so the caller sees a clean Rust-side error.
    pub fn set(&self, policy: &str, set_by_sid: Option<&str>, now: i64) -> StorageResult<()> {
        if !VALID_POLICY_SLUGS.contains(&policy) {
            return Err(StorageError::Internal(format!(
                "unknown apply-failure-policy slug {policy:?}"
            )));
        }
        self.conn
            .execute(
                "INSERT INTO apply_failure_policy_settings
                 (id, policy, set_by_sid, set_at)
                 VALUES (1, ?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET
                     policy = excluded.policy,
                     set_by_sid = excluded.set_by_sid,
                     set_at = excluded.set_at",
                params![policy, set_by_sid, now],
            )
            .map_err(|e| {
                StorageError::Internal(format!("apply_failure_policy_settings set: {e}"))
            })?;
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
    fn default_slug_is_best_effort() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = ApplyFailurePolicySettingsRepository::new(&conn);
        let r = repo.get_or_default().expect("get");
        assert_eq!(r.policy, "best-effort");
        assert!(r.set_by_sid.is_none());
        assert_eq!(r.set_at, 0);
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = ApplyFailurePolicySettingsRepository::new(&conn);
        repo.set("best-effort", Some("S-1-5-21-A"), 1_700_000_000)
            .expect("set");
        let r = repo.get_or_default().expect("get");
        assert_eq!(r.policy, "best-effort");
        assert_eq!(r.set_by_sid, Some("S-1-5-21-A".to_string()));
        assert_eq!(r.set_at, 1_700_000_000);
    }

    #[test]
    fn set_replaces_previous_row() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = ApplyFailurePolicySettingsRepository::new(&conn);
        repo.set("best-effort", None, 100).expect("first");
        repo.set("pre-flight-then-all-or-nothing", Some("S-X"), 200)
            .expect("second");
        let r = repo.get_or_default().expect("get");
        assert_eq!(r.policy, "pre-flight-then-all-or-nothing");
        assert_eq!(r.set_by_sid, Some("S-X".to_string()));
        assert_eq!(r.set_at, 200);
        // Only one row.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM apply_failure_policy_settings",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 1);
    }

    #[test]
    fn set_rejects_unknown_slug() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = ApplyFailurePolicySettingsRepository::new(&conn);
        assert!(repo.set("yolo", None, 0).is_err());
    }

    #[test]
    fn sql_check_rejects_unknown_slug_on_direct_insert() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let result = conn.execute(
            "INSERT INTO apply_failure_policy_settings (id, policy, set_at)
             VALUES (1, 'yolo', 0)",
            [],
        );
        assert!(result.is_err(), "SQL CHECK must reject unknown slug");
    }
}
