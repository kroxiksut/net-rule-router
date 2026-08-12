//! `retention_settings` singleton repository + retention policy DTO.
//!
//! The settings drive `RevisionsRepository::prune_by_retention`. Defaults
//! are designed to cover a normal user (~3 months of history) without
//! letting an automated test or runaway script bloat the DB.
//!
//! Validation ranges match the GUI SpinBox bounds:
//!
//! | Field                  | Range        | Default |
//! |------------------------|--------------|---------|
//! | `superseded_days`      | 7..=365      | 30      |
//! | `superseded_count_cap` | 20..=1000    | 100     |
//! | `rejected_days`        | 1..=90       | 7       |
//! | `rolledback_days`      | 1..=90       | 14      |
//! | `rolledback_count_cap` | 5..=100      | 20      |
//! | `pin_lkg`              | bool         | true    |
//!
//! Out-of-range values are rejected by both [`RetentionSettings::validate`]
//! (Rust-side) and the SQL CHECK constraint (storage-side), so even a
//! buggy client cannot stuff a 10-year retention into the DB.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── DTO ───────────────────────────────────────────────────────────────────────

/// User-visible retention policy. Drives revision GC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionSettings {
    pub superseded_days: u32,
    pub superseded_count_cap: u32,
    pub rejected_days: u32,
    pub rolledback_days: u32,
    pub rolledback_count_cap: u32,
    /// When `true`, the most recent superseded revision (the LKG) is
    /// excluded from retention sweeps regardless of count cap.
    pub pin_lkg: bool,
    /// Wall-clock seconds of the last cleanup pass, or `None` if no
    /// pass has run yet.
    pub last_cleanup_at: Option<i64>,
    /// Wall-clock seconds the row was last written (defaults insert).
    pub updated_at: i64,
}

impl RetentionSettings {
    /// Unit tests assert these match the schema CHECK midpoints / GUI
    /// tooltip text.
    pub const DEFAULT: Self = Self {
        superseded_days: 30,
        superseded_count_cap: 100,
        rejected_days: 7,
        rolledback_days: 14,
        rolledback_count_cap: 20,
        pin_lkg: true,
        last_cleanup_at: None,
        updated_at: 0,
    };

    /// Validates the value ranges match the SQL CHECK constraints. The
    /// repository's `set` method calls this so callers get a clean
    /// error message rather than `SqliteFailure(ConstraintViolation)`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(7..=365).contains(&self.superseded_days) {
            return Err("superseded_days must be in 7..=365");
        }
        if !(20..=1000).contains(&self.superseded_count_cap) {
            return Err("superseded_count_cap must be in 20..=1000");
        }
        if !(1..=90).contains(&self.rejected_days) {
            return Err("rejected_days must be in 1..=90");
        }
        if !(1..=90).contains(&self.rolledback_days) {
            return Err("rolledback_days must be in 1..=90");
        }
        if !(5..=100).contains(&self.rolledback_count_cap) {
            return Err("rolledback_count_cap must be in 5..=100");
        }
        Ok(())
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

pub struct RetentionSettingsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> RetentionSettingsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row; if absent, returns
    /// [`RetentionSettings::DEFAULT`] (with `updated_at = 0`). The
    /// caller is free to materialise the defaults via [`set`] when it
    /// wants to record an explicit default install.
    pub fn get_or_default(&self) -> StorageResult<RetentionSettings> {
        let row = self
            .conn
            .query_row(
                "SELECT superseded_days, superseded_count_cap, rejected_days,
                        rolledback_days, rolledback_count_cap, pin_lkg,
                        last_cleanup_at, updated_at
                 FROM retention_settings WHERE id = 1",
                [],
                |row| {
                    Ok(RetentionSettings {
                        superseded_days: row.get::<_, i64>(0)? as u32,
                        superseded_count_cap: row.get::<_, i64>(1)? as u32,
                        rejected_days: row.get::<_, i64>(2)? as u32,
                        rolledback_days: row.get::<_, i64>(3)? as u32,
                        rolledback_count_cap: row.get::<_, i64>(4)? as u32,
                        pin_lkg: row.get::<_, i64>(5)? != 0,
                        last_cleanup_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("retention_settings get: {e}")))?;
        Ok(row.unwrap_or(RetentionSettings::DEFAULT))
    }

    /// Inserts or replaces the singleton row. `updated_at` is set to
    /// `now`; `last_cleanup_at` is preserved from the supplied DTO so
    /// callers can save settings without resetting cleanup history.
    pub fn set(&self, settings: &RetentionSettings, now: i64) -> StorageResult<()> {
        settings
            .validate()
            .map_err(|reason| StorageError::Internal(format!("retention validation: {reason}")))?;
        self.conn
            .execute(
                "INSERT INTO retention_settings
                 (id, superseded_days, superseded_count_cap, rejected_days,
                  rolledback_days, rolledback_count_cap, pin_lkg,
                  last_cleanup_at, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(id) DO UPDATE SET
                     superseded_days = excluded.superseded_days,
                     superseded_count_cap = excluded.superseded_count_cap,
                     rejected_days = excluded.rejected_days,
                     rolledback_days = excluded.rolledback_days,
                     rolledback_count_cap = excluded.rolledback_count_cap,
                     pin_lkg = excluded.pin_lkg,
                     last_cleanup_at = excluded.last_cleanup_at,
                     updated_at = excluded.updated_at",
                params![
                    settings.superseded_days as i64,
                    settings.superseded_count_cap as i64,
                    settings.rejected_days as i64,
                    settings.rolledback_days as i64,
                    settings.rolledback_count_cap as i64,
                    settings.pin_lkg as i64,
                    settings.last_cleanup_at,
                    now,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("retention_settings set: {e}")))?;
        Ok(())
    }

    /// Records that a cleanup pass just ran. Caller has already deleted
    /// the rows; this only updates the `last_cleanup_at` audit column.
    pub fn touch_last_cleanup(&self, now: i64) -> StorageResult<()> {
        // Upsert so that the very first cleanup pass also writes a row.
        self.conn
            .execute(
                "INSERT INTO retention_settings
                 (id, superseded_days, superseded_count_cap, rejected_days,
                  rolledback_days, rolledback_count_cap, pin_lkg,
                  last_cleanup_at, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(id) DO UPDATE SET
                     last_cleanup_at = excluded.last_cleanup_at",
                params![
                    RetentionSettings::DEFAULT.superseded_days as i64,
                    RetentionSettings::DEFAULT.superseded_count_cap as i64,
                    RetentionSettings::DEFAULT.rejected_days as i64,
                    RetentionSettings::DEFAULT.rolledback_days as i64,
                    RetentionSettings::DEFAULT.rolledback_count_cap as i64,
                    RetentionSettings::DEFAULT.pin_lkg as i64,
                    now,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("retention_settings touch: {e}")))?;
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
    fn defaults_match_design_values() {
        let d = RetentionSettings::DEFAULT;
        assert_eq!(d.superseded_days, 30);
        assert_eq!(d.superseded_count_cap, 100);
        assert_eq!(d.rejected_days, 7);
        assert_eq!(d.rolledback_days, 14);
        assert_eq!(d.rolledback_count_cap, 20);
        assert!(d.pin_lkg);
    }

    #[test]
    fn validate_accepts_default() {
        assert!(RetentionSettings::DEFAULT.validate().is_ok());
    }

    #[test]
    fn validate_rejects_out_of_range_values() {
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_days = 6;
        assert!(s.validate().is_err());
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_days = 366;
        assert!(s.validate().is_err());
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_count_cap = 19;
        assert!(s.validate().is_err());
        let mut s = RetentionSettings::DEFAULT;
        s.rejected_days = 0;
        assert!(s.validate().is_err());
        let mut s = RetentionSettings::DEFAULT;
        s.rolledback_count_cap = 4;
        assert!(s.validate().is_err());
    }

    #[test]
    fn get_or_default_returns_defaults_on_fresh_db() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RetentionSettingsRepository::new(&conn);
        let s = repo.get_or_default().expect("get");
        assert_eq!(s, RetentionSettings::DEFAULT);
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RetentionSettingsRepository::new(&conn);
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_days = 90;
        s.pin_lkg = false;
        s.last_cleanup_at = Some(1_700_000_000);
        repo.set(&s, 1_700_001_000).expect("set");
        let got = repo.get_or_default().expect("get");
        assert_eq!(got.superseded_days, 90);
        assert!(!got.pin_lkg);
        assert_eq!(got.last_cleanup_at, Some(1_700_000_000));
        assert_eq!(got.updated_at, 1_700_001_000);
    }

    #[test]
    fn set_rejects_invalid_values_via_rust_validation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RetentionSettingsRepository::new(&conn);
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_days = 5; // below floor
        assert!(repo.set(&s, 0).is_err());
    }

    #[test]
    fn sql_check_blocks_out_of_range_direct_insert() {
        // Bypass the repo and try a direct INSERT with bad values.
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let result = conn.execute(
            "INSERT INTO retention_settings
             (id, superseded_days, superseded_count_cap, rejected_days,
              rolledback_days, rolledback_count_cap, pin_lkg, last_cleanup_at, updated_at)
             VALUES (1, 5, 100, 7, 14, 20, 1, NULL, 0)",
            [],
        );
        assert!(result.is_err(), "SQL CHECK must reject superseded_days=5");
    }

    #[test]
    fn touch_last_cleanup_creates_row_when_absent() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RetentionSettingsRepository::new(&conn);
        repo.touch_last_cleanup(1_700_000_111).expect("touch");
        let s = repo.get_or_default().expect("get");
        assert_eq!(s.last_cleanup_at, Some(1_700_000_111));
        assert_eq!(
            s.superseded_days,
            RetentionSettings::DEFAULT.superseded_days
        );
    }

    #[test]
    fn touch_last_cleanup_preserves_other_settings() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = RetentionSettingsRepository::new(&conn);
        let mut s = RetentionSettings::DEFAULT;
        s.superseded_days = 200;
        repo.set(&s, 1_700_000_000).expect("set");
        repo.touch_last_cleanup(1_700_000_999).expect("touch");
        let got = repo.get_or_default().expect("get");
        assert_eq!(got.superseded_days, 200);
        assert_eq!(got.last_cleanup_at, Some(1_700_000_999));
    }
}
