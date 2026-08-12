//! Block T (traffic counter) — service-global traffic-statistics settings
//! singleton (`traffic_stats_settings`).
//!
//! Lives in the **service-critical** state DB, deliberately NOT in the
//! rebuildable `nrr_traffic_stats.db`: a ledger rebuild must never lose the
//! user's configuration. Holds the master accounting toggle, the opt-in
//! loopback / virtual category toggles, and the daily-history retention window.
//! The Today/Session display period is a device-specific UI preference and lives
//! in `UiPreferences`, not here.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

// ── DTO ───────────────────────────────────────────────────────────────────────

/// Service-global traffic-statistics configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficStatsSettings {
    /// Master accounting toggle. When `false` the sampler stops recording.
    pub enabled: bool,
    /// Count loopback (localhost) traffic as its own line. Default off; when
    /// flipped on the ledger records from that moment forward.
    pub count_loopback: bool,
    /// Count virtual (VM host-only) adapters as an aggregate. Default off.
    pub count_virtual: bool,
    /// Days of daily history to retain before the sweep drops older rows.
    pub retention_days: u32,
    /// Wall-clock seconds the row was last written.
    pub updated_at: i64,
}

impl TrafficStatsSettings {
    /// Retention floor/ceiling — mirrored by the SQL CHECK constraint and the
    /// GUI SpinBox bounds (backend is the SSOT).
    pub const RETENTION_MIN: u32 = 7;
    pub const RETENTION_MAX: u32 = 3650;

    /// Design defaults: accounting on, opt-in categories off, one year retained.
    pub const DEFAULT: Self = Self {
        enabled: true,
        count_loopback: false,
        count_virtual: false,
        retention_days: 365,
        updated_at: 0,
    };

    /// Validates ranges against the SQL CHECK so callers get a clean error
    /// rather than a `ConstraintViolation`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(Self::RETENTION_MIN..=Self::RETENTION_MAX).contains(&self.retention_days) {
            return Err("retention_days must be in 7..=3650");
        }
        Ok(())
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

pub struct TrafficStatsSettingsRepository<'c> {
    conn: &'c Connection,
}

impl<'c> TrafficStatsSettingsRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row, or [`TrafficStatsSettings::DEFAULT`] if absent.
    pub fn get_or_default(&self) -> StorageResult<TrafficStatsSettings> {
        let row = self
            .conn
            .query_row(
                "SELECT enabled, count_loopback, count_virtual, retention_days, updated_at
                 FROM traffic_stats_settings WHERE id = 1",
                [],
                |r| {
                    Ok(TrafficStatsSettings {
                        enabled: r.get::<_, i64>(0)? != 0,
                        count_loopback: r.get::<_, i64>(1)? != 0,
                        count_virtual: r.get::<_, i64>(2)? != 0,
                        retention_days: r.get::<_, i64>(3)? as u32,
                        updated_at: r.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("traffic_stats_settings get: {e}")))?;
        Ok(row.unwrap_or(TrafficStatsSettings::DEFAULT))
    }

    /// Inserts or replaces the singleton row; `updated_at` is set to `now`.
    pub fn set(&self, settings: &TrafficStatsSettings, now: i64) -> StorageResult<()> {
        settings.validate().map_err(|reason| {
            StorageError::Internal(format!("traffic_stats_settings validation: {reason}"))
        })?;
        self.conn
            .execute(
                "INSERT INTO traffic_stats_settings
                 (id, enabled, count_loopback, count_virtual, retention_days, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                     enabled        = excluded.enabled,
                     count_loopback = excluded.count_loopback,
                     count_virtual  = excluded.count_virtual,
                     retention_days = excluded.retention_days,
                     updated_at     = excluded.updated_at",
                params![
                    settings.enabled as i64,
                    settings.count_loopback as i64,
                    settings.count_virtual as i64,
                    settings.retention_days as i64,
                    now,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("traffic_stats_settings set: {e}")))?;
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
    fn defaults_match_design() {
        let d = TrafficStatsSettings::DEFAULT;
        assert!(d.enabled);
        assert!(!d.count_loopback);
        assert!(!d.count_virtual);
        assert_eq!(d.retention_days, 365);
    }

    #[test]
    fn validate_bounds() {
        assert!(TrafficStatsSettings::DEFAULT.validate().is_ok());
        let mut s = TrafficStatsSettings::DEFAULT;
        s.retention_days = 6;
        assert!(s.validate().is_err());
        s.retention_days = 3651;
        assert!(s.validate().is_err());
        s.retention_days = 7;
        assert!(s.validate().is_ok());
        s.retention_days = 3650;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn get_or_default_on_fresh_db() {
        let dir = tempfile::tempdir().expect("dir");
        let conn = open_state_db(&dir);
        let repo = TrafficStatsSettingsRepository::new(&conn);
        assert_eq!(
            repo.get_or_default().expect("get"),
            TrafficStatsSettings::DEFAULT
        );
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tempfile::tempdir().expect("dir");
        let conn = open_state_db(&dir);
        let repo = TrafficStatsSettingsRepository::new(&conn);
        let s = TrafficStatsSettings {
            enabled: false,
            count_loopback: true,
            count_virtual: true,
            retention_days: 90,
            updated_at: 0,
        };
        repo.set(&s, 1_700_000_000).expect("set");
        let got = repo.get_or_default().expect("get");
        assert!(!got.enabled);
        assert!(got.count_loopback);
        assert!(got.count_virtual);
        assert_eq!(got.retention_days, 90);
        assert_eq!(got.updated_at, 1_700_000_000);
    }

    #[test]
    fn set_rejects_out_of_range() {
        let dir = tempfile::tempdir().expect("dir");
        let conn = open_state_db(&dir);
        let repo = TrafficStatsSettingsRepository::new(&conn);
        let mut s = TrafficStatsSettings::DEFAULT;
        s.retention_days = 5;
        assert!(repo.set(&s, 0).is_err());
    }

    #[test]
    fn sql_check_blocks_direct_out_of_range_insert() {
        let dir = tempfile::tempdir().expect("dir");
        let conn = open_state_db(&dir);
        let result = conn.execute(
            "INSERT INTO traffic_stats_settings
             (id, enabled, count_loopback, count_virtual, retention_days, updated_at)
             VALUES (1, 1, 0, 0, 5, 0)",
            [],
        );
        assert!(result.is_err(), "SQL CHECK must reject retention_days=5");
    }
}
