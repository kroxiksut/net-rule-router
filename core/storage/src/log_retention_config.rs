//! `log_retention_config` singleton repository + DTO.
//!
//! Holds the user-configurable retention for the OPERATIONAL NDJSON logs and
//! the AUDIT NDJSON trail (age + total-size caps). The service-side cleanup
//! tasks (`nrr_diagnostics` `CleanupJob::run_logs` / `run_audit`) read this at
//! startup and prune accordingly. Defaults mirror CLAUDE.md:
//!
//! | Field                  | Range              | Default    |
//! |------------------------|--------------------|------------|
//! | `log_max_age_days`     | 1..=3650           | 90         |
//! | `log_max_size_bytes`   | 0..=1 TiB          | 50 MiB     |
//! | `audit_max_age_days`   | 1..=3650           | 365        |
//! | `audit_max_size_bytes` | 0..=1 TiB          | 50 MiB     |
//!
//! `0` bytes = age-only (no size cap). Ranges are wide so a GUI value
//! (value × unit) is never client-valid-but-storage-rejected. Both
//! [`LogRetentionConfig::validate`] and the SQL CHECK guard the bounds.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{StorageError, StorageResult};

const MAX_SIZE_BYTES: u64 = 1_099_511_627_776; // 1 TiB
const MIB_50: u64 = 52_428_800;

// ── DTO ───────────────────────────────────────────────────────────────────────

/// User-configurable operational-log + audit NDJSON retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRetentionConfig {
    /// Max age (days) of operational NDJSON logs before pruning.
    pub log_max_age_days: u32,
    /// Max total size (bytes) of operational NDJSON logs; `0` = no size cap.
    pub log_max_size_bytes: u64,
    /// Max age (days) of the audit NDJSON trail before pruning.
    pub audit_max_age_days: u32,
    /// Max total size (bytes) of the audit NDJSON trail; `0` = no size cap.
    pub audit_max_size_bytes: u64,
    /// Wall-clock seconds the row was last written.
    pub updated_at: i64,
}

impl LogRetentionConfig {
    /// CLAUDE.md defaults: logs 90 days / 50 MiB, audit 365 days / 50 MiB.
    pub const DEFAULT: Self = Self {
        log_max_age_days: 90,
        log_max_size_bytes: MIB_50,
        audit_max_age_days: 365,
        audit_max_size_bytes: MIB_50,
        updated_at: 0,
    };

    /// Validates the value ranges match the SQL CHECK constraints so callers
    /// get a clean error rather than a `ConstraintViolation`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=3650).contains(&self.log_max_age_days) {
            return Err("log_max_age_days must be in 1..=3650");
        }
        if self.log_max_size_bytes > MAX_SIZE_BYTES {
            return Err("log_max_size_bytes must be <= 1 TiB");
        }
        if !(1..=3650).contains(&self.audit_max_age_days) {
            return Err("audit_max_age_days must be in 1..=3650");
        }
        if self.audit_max_size_bytes > MAX_SIZE_BYTES {
            return Err("audit_max_size_bytes must be <= 1 TiB");
        }
        Ok(())
    }
}

// ── Repository ────────────────────────────────────────────────────────────────

pub struct LogRetentionConfigRepository<'c> {
    conn: &'c Connection,
}

impl<'c> LogRetentionConfigRepository<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    /// Reads the singleton row; if absent, returns [`LogRetentionConfig::DEFAULT`].
    pub fn get_or_default(&self) -> StorageResult<LogRetentionConfig> {
        let row = self
            .conn
            .query_row(
                "SELECT log_max_age_days, log_max_size_bytes,
                        audit_max_age_days, audit_max_size_bytes, updated_at
                 FROM log_retention_config WHERE id = 1",
                [],
                |row| {
                    Ok(LogRetentionConfig {
                        log_max_age_days: row.get::<_, i64>(0)? as u32,
                        log_max_size_bytes: row.get::<_, i64>(1)? as u64,
                        audit_max_age_days: row.get::<_, i64>(2)? as u32,
                        audit_max_size_bytes: row.get::<_, i64>(3)? as u64,
                        updated_at: row.get(4)?,
                    })
                },
            )
            .optional()
            .map_err(|e| StorageError::Internal(format!("log_retention_config get: {e}")))?;
        Ok(row.unwrap_or(LogRetentionConfig::DEFAULT))
    }

    /// Inserts or replaces the singleton row. `updated_at` is set to `now`.
    pub fn set(&self, cfg: &LogRetentionConfig, now: i64) -> StorageResult<()> {
        cfg.validate().map_err(|reason| {
            StorageError::Internal(format!("log_retention_config validation: {reason}"))
        })?;
        self.conn
            .execute(
                "INSERT INTO log_retention_config
                 (id, log_max_age_days, log_max_size_bytes,
                  audit_max_age_days, audit_max_size_bytes, updated_at)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(id) DO UPDATE SET
                     log_max_age_days = excluded.log_max_age_days,
                     log_max_size_bytes = excluded.log_max_size_bytes,
                     audit_max_age_days = excluded.audit_max_age_days,
                     audit_max_size_bytes = excluded.audit_max_size_bytes,
                     updated_at = excluded.updated_at",
                params![
                    cfg.log_max_age_days as i64,
                    cfg.log_max_size_bytes as i64,
                    cfg.audit_max_age_days as i64,
                    cfg.audit_max_size_bytes as i64,
                    now,
                ],
            )
            .map_err(|e| StorageError::Internal(format!("log_retention_config set: {e}")))?;
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
        let d = LogRetentionConfig::DEFAULT;
        assert_eq!(d.log_max_age_days, 90);
        assert_eq!(d.log_max_size_bytes, 52_428_800);
        assert_eq!(d.audit_max_age_days, 365);
        assert_eq!(d.audit_max_size_bytes, 52_428_800);
    }

    #[test]
    fn validate_accepts_default_and_zero_size() {
        assert!(LogRetentionConfig::DEFAULT.validate().is_ok());
        let mut c = LogRetentionConfig::DEFAULT;
        c.log_max_size_bytes = 0; // age-only
        c.audit_max_size_bytes = 0;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_out_of_range() {
        let mut c = LogRetentionConfig::DEFAULT;
        c.log_max_age_days = 0;
        assert!(c.validate().is_err());
        let mut c = LogRetentionConfig::DEFAULT;
        c.log_max_age_days = 3651;
        assert!(c.validate().is_err());
        let mut c = LogRetentionConfig::DEFAULT;
        c.audit_max_size_bytes = MAX_SIZE_BYTES + 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn get_or_default_returns_defaults_on_fresh_db() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = LogRetentionConfigRepository::new(&conn);
        assert_eq!(
            repo.get_or_default().expect("get"),
            LogRetentionConfig::DEFAULT
        );
    }

    #[test]
    fn set_then_get_roundtrip() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = LogRetentionConfigRepository::new(&conn);
        let mut c = LogRetentionConfig::DEFAULT;
        c.log_max_age_days = 30;
        c.log_max_size_bytes = 104_857_600; // 100 MiB
        c.audit_max_age_days = 730;
        repo.set(&c, 1_700_001_000).expect("set");
        let got = repo.get_or_default().expect("get");
        assert_eq!(got.log_max_age_days, 30);
        assert_eq!(got.log_max_size_bytes, 104_857_600);
        assert_eq!(got.audit_max_age_days, 730);
        assert_eq!(got.updated_at, 1_700_001_000);
    }

    #[test]
    fn set_rejects_invalid_via_rust_validation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let repo = LogRetentionConfigRepository::new(&conn);
        let mut c = LogRetentionConfig::DEFAULT;
        c.log_max_age_days = 0;
        assert!(repo.set(&c, 0).is_err());
    }

    #[test]
    fn sql_check_blocks_out_of_range_direct_insert() {
        let dir = tempfile::tempdir().expect("temp dir");
        let conn = open_state_db(&dir);
        let result = conn.execute(
            "INSERT INTO log_retention_config
             (id, log_max_age_days, log_max_size_bytes,
              audit_max_age_days, audit_max_size_bytes, updated_at)
             VALUES (1, 0, 52428800, 365, 52428800, 0)",
            [],
        );
        assert!(result.is_err(), "SQL CHECK must reject log_max_age_days=0");
    }
}
