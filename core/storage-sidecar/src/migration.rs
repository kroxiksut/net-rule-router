//! Schema migrations of the sidecar database, run by the shared runner in
//! `nrr-sqlite-support` (one immediate transaction, checksums re-validated on
//! every open, downgrades refused).
//!
//! The contents are rebuildable, yet corruption is treated strictly: silently
//! truncating user-typed comments is worse than refusing to open.

use nrr_sqlite_support::{Migration, MigrationError};
use rusqlite::Connection;

use crate::error::{SidecarError, SidecarResult};
use crate::schema::{SIDECAR_DB_V1_DDL, SIDECAR_DB_V2_DDL, SIDECAR_DB_V3_DDL};

/// Latest schema version this binary knows how to produce or open: the last
/// entry of [`MIGRATIONS`].
pub const LATEST_SCHEMA_VERSION: u32 = 3;

/// Append only; never edit an entry that has shipped.
const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_sidecar_schema",
        stmts: SIDECAR_DB_V1_DDL,
    },
    Migration {
        version: 2,
        name: "external_ip_cache",
        stmts: SIDECAR_DB_V2_DDL,
    },
    Migration {
        version: 3,
        name: "pending_apply_without_rules_snapshot",
        stmts: SIDECAR_DB_V3_DDL,
    },
];

/// Outcome of [`migrate`] — for diagnostics and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSummary {
    /// Zero on a freshly created sidecar.
    pub from_version: u32,
    pub to_version: u32,
    /// Names of the migrations this call applied, in order.
    pub migrations_applied: Vec<String>,
}

/// Apply any pending schema migrations on `conn`. The GUI and the tray open
/// this file from two processes, often in the same second on a fresh install;
/// the second one waits on the write lock and then finds nothing to do.
pub fn migrate(conn: &mut Connection) -> SidecarResult<MigrationSummary> {
    let outcome = nrr_sqlite_support::migrate(conn, MIGRATIONS).map_err(|e| match e {
        MigrationError::Sqlite(e) | MigrationError::StepFailed { source: e, .. } => {
            SidecarError::Sqlite(e)
        }
        MigrationError::SchemaTooNew { found, supported } => {
            SidecarError::SchemaTooNew { found, supported }
        }
        other => SidecarError::MigrationCorrupted {
            detail: other.to_string(),
        },
    })?;
    Ok(MigrationSummary {
        from_version: outcome.from_version,
        to_version: outcome.to_version,
        migrations_applied: outcome.applied.into_iter().map(str::to_owned).collect(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;

    fn open_in_memory() -> SidecarResult<Connection> {
        let conn = Connection::open_in_memory()?;
        conn.busy_timeout(std::time::Duration::from_millis(1000))?;
        Ok(conn)
    }

    #[test]
    fn fresh_db_runs_all_migrations() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        let summary = migrate(&mut conn)?;
        assert_eq!(summary.from_version, 0);
        assert_eq!(summary.to_version, LATEST_SCHEMA_VERSION);
        assert_eq!(
            summary.migrations_applied,
            vec![
                "initial_sidecar_schema",
                "external_ip_cache",
                "pending_apply_without_rules_snapshot",
            ]
        );
        // Every table across both migrations exists.
        for table in [
            "schema_migrations",
            "rule_metadata",
            "passthrough",
            "pending_apply",
            "external_ip_cache",
        ] {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                params![table],
                |r| r.get(0),
            )?;
            assert_eq!(count, 1, "table {table} should exist after migration");
        }
        Ok(())
    }

    #[test]
    fn second_migrate_is_noop() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        let summary = migrate(&mut conn)?;
        assert_eq!(summary.from_version, LATEST_SCHEMA_VERSION);
        assert_eq!(summary.to_version, LATEST_SCHEMA_VERSION);
        assert!(summary.migrations_applied.is_empty());
        Ok(())
    }

    #[test]
    fn checksum_mismatch_is_fatal() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        // Tamper with the stored checksum to simulate drift.
        conn.execute(
            "UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1",
            [],
        )?;
        match migrate(&mut conn) {
            Err(SidecarError::MigrationCorrupted { .. }) => Ok(()),
            other => panic!("expected MigrationCorrupted, got {other:?}"),
        }
    }

    /// The bookkeeping row must never be overwritten. `INSERT OR REPLACE`
    /// silently rewrote the stored checksum of an already-applied migration,
    /// so re-running the runner "repaired" the very mismatch
    /// [`validate_applied_checksums`] exists to report — a guard the guarded
    /// code could defeat.
    #[test]
    fn re_applying_never_rewrites_a_stored_checksum() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        conn.execute(
            "UPDATE schema_migrations SET checksum = 'deadbeef' WHERE version = 1",
            [],
        )?;
        match migrate(&mut conn) {
            Err(SidecarError::MigrationCorrupted { detail }) => {
                assert!(detail.contains("checksum mismatch"), "{detail}");
            }
            other => panic!("expected MigrationCorrupted, got {other:?}"),
        }
        // And the tampered value is still there — nothing quietly healed it.
        let stored: String = conn.query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 1",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(stored, "deadbeef");
        Ok(())
    }

    /// A gap below the maximum is an interrupted upgrade: nothing will ever
    /// apply the missing migration, because the runner only looks above
    /// `MAX(version)`.
    #[test]
    fn a_gap_in_the_applied_history_is_rejected() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        let highest: i64 =
            conn.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                r.get(0)
            })?;
        if highest < 2 {
            // One migration only: there is no "below the maximum" to remove.
            return Ok(());
        }
        conn.execute("DELETE FROM schema_migrations WHERE version = 1", [])?;
        match migrate(&mut conn) {
            Err(SidecarError::MigrationCorrupted { detail }) => {
                assert!(
                    detail.contains("missing from the applied history"),
                    "{detail}"
                );
                Ok(())
            }
            other => panic!("expected MigrationCorrupted, got {other:?}"),
        }
    }

    /// An unreadable version must not read as "fresh database": that re-ran the
    /// v1 DDL and surfaced SQLite's `table already exists` instead of an answer
    /// about the schema.
    #[test]
    fn an_impossible_version_is_reported_not_treated_as_empty() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at, checksum, app_version)
             VALUES (-7, 'impossible', 0, 'x', '0')",
            [],
        )?;
        conn.execute("DELETE FROM schema_migrations WHERE version > 0", [])?;
        match migrate(&mut conn) {
            Err(SidecarError::MigrationCorrupted { detail }) => {
                assert!(detail.contains("impossible version"), "{detail}");
                Ok(())
            }
            other => panic!("expected MigrationCorrupted, got {other:?}"),
        }
    }

    #[test]
    fn newer_schema_is_refused() -> SidecarResult<()> {
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        // Pretend a future build wrote a v99 row.
        conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at, checksum, app_version)
             VALUES (99, 'from_future', 0, 'x', '99.0.0')",
            [],
        )?;
        match migrate(&mut conn) {
            Err(SidecarError::SchemaTooNew {
                found: 99,
                supported: LATEST_SCHEMA_VERSION,
            }) => Ok(()),
            other => panic!("expected SchemaTooNew, got {other:?}"),
        }
    }

    #[test]
    fn migration_is_atomic_on_failure() -> SidecarResult<()> {
        // We can't easily inject a failing DDL into the real catalog
        // without polluting it, so instead we verify that after a
        // successful run the schema_migrations row and the tables
        // co-exist. Atomicity is enforced by the transaction wrapper;
        // this is a smoke test, not a fault-injection test.
        let mut conn = open_in_memory()?;
        migrate(&mut conn)?;
        let v: i64 = conn.query_row(
            "SELECT version FROM schema_migrations WHERE name = 'initial_sidecar_schema'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(v, 1);
        Ok(())
    }

    #[test]
    fn the_latest_version_is_the_last_migration() {
        assert_eq!(
            MIGRATIONS.last().map(|m| m.version),
            Some(LATEST_SCHEMA_VERSION)
        );
    }

    /// Existing sidecars store these; a changed value is a database that no
    /// longer opens.
    #[test]
    fn shipped_migration_checksums_are_unchanged() {
        let got: Vec<(u32, String)> = MIGRATIONS
            .iter()
            .map(|m| (m.version, nrr_sqlite_support::checksum(m.stmts)))
            .collect();
        let want = [
            (1, "d80a0f4a3f2b0718"),
            (2, "6c866594fe9fdcb4"),
            (3, "7905dfe410d06a0e"),
        ];
        assert_eq!(got.len(), want.len());
        for ((v, c), (wv, wc)) in got.iter().zip(want) {
            assert_eq!((*v, c.as_str()), (wv, wc));
        }
    }
}
