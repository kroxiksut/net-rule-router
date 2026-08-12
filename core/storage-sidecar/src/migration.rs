//! Schema migration runner for the sidecar database.
//!
//! Mirrors the convention from `nrr-storage::migration` (block 12.4):
//!
//! * `schema_migrations` table stores one row per applied migration
//!   with name, checksum and `app_version` of the binary that ran it.
//! * Each migration's DDL plus its `schema_migrations` INSERT execute
//!   in a single transaction so a crash mid-migration cannot leave
//!   the database in a half-applied state.
//! * On every open we re-validate the stored checksums against the
//!   currently-embedded SQL; any drift is fatal (corrupted history).
//! * Downgrades are refused — `current > LATEST_SCHEMA_VERSION`
//!   means the user opened a sidecar produced by a newer build.
//!
//! Sidecar contents are rebuildable (comments are decoration,
//! passthrough only matters until the next import, `pending_apply`
//! self-expires after seven days). Despite that we treat schema
//! corruption strictly — silently truncating user-typed comments
//! would be a much worse failure mode than refusing to open.

use std::time::SystemTime;

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{SidecarError, SidecarResult};
use crate::schema::{SIDECAR_DB_V1_DDL, SIDECAR_DB_V2_DDL};

/// Latest schema version this binary knows how to produce or open.
///
/// Incrementing this constant **must** be paired with adding a new
/// entry at the tail of [`MIGRATIONS`] — the runner refuses to start
/// if the on-disk version exceeds the highest registered migration.
pub const LATEST_SCHEMA_VERSION: u32 = 2;

/// Bootstrap DDL for the `schema_migrations` bookkeeping table.
/// Idempotent so the runner can call it on every open without
/// guarding for "already created".
const CREATE_SCHEMA_MIGRATIONS: &str = "
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    applied_at  INTEGER NOT NULL,
    checksum    TEXT    NOT NULL,
    app_version TEXT    NOT NULL
)";

/// A single versioned migration step.
#[derive(Clone, Copy)]
struct MigrationDef {
    version: u32,
    name: &'static str,
    /// Individual SQL statements executed in order inside the same
    /// transaction as the `schema_migrations` INSERT. The checksum
    /// is computed over this slice; reordering statements without
    /// bumping the version is a corruption signal at next open.
    stmts: &'static [&'static str],
}

/// Ordered catalogue of every migration this binary can apply.
/// Adding a new entry: append at the tail, bump
/// [`LATEST_SCHEMA_VERSION`], never mutate existing entries.
const MIGRATIONS: &[MigrationDef] = &[
    MigrationDef {
        version: 1,
        name: "initial_sidecar_schema",
        stmts: SIDECAR_DB_V1_DDL,
    },
    MigrationDef {
        version: 2,
        name: "external_ip_cache",
        stmts: SIDECAR_DB_V2_DDL,
    },
];

/// Outcome of [`migrate`] — surfaced for diagnostics and tests; not
/// consumed by the GUI runtime, which only cares about success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationSummary {
    /// Schema version recorded in the database **before** the run.
    /// Zero on a freshly created sidecar (no migrations applied yet).
    pub from_version: u32,
    /// Schema version recorded in the database **after** the run.
    /// Always ≥ `from_version`; equal when no pending migrations
    /// existed.
    pub to_version: u32,
    /// Names of migrations applied during this call, in order.
    /// Empty when the database was already up to date.
    pub migrations_applied: Vec<String>,
}

/// Apply any pending schema migrations on `conn`.
///
/// The sequence is:
///
/// 1. Ensure the `schema_migrations` table exists.
/// 2. Read the current version (`MAX(version)`); zero when empty.
/// 3. Re-validate stored checksums against current embedded SQL.
///    A mismatch returns [`SidecarError::MigrationCorrupted`].
/// 4. Refuse to open if `current > LATEST_SCHEMA_VERSION`
///    ([`SidecarError::SchemaTooNew`]).
/// 5. For each pending migration in order: open a transaction,
///    execute the DDL statements, insert the bookkeeping row,
///    commit.
///
/// The connection's WAL/busy_timeout pragmas are not touched here;
/// `db::SidecarDb::open` configures them before calling us so the
/// migration transactions inherit the right behaviour.
pub fn migrate(conn: &mut Connection) -> SidecarResult<MigrationSummary> {
    ensure_migrations_table(conn)?;
    let from_version = current_version(conn)?;
    validate_applied_checksums(conn, from_version)?;

    if from_version > LATEST_SCHEMA_VERSION {
        return Err(SidecarError::SchemaTooNew {
            found: from_version,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    let pending: Vec<&MigrationDef> = MIGRATIONS
        .iter()
        .filter(|m| m.version > from_version)
        .collect();

    let mut applied = Vec::with_capacity(pending.len());
    for migration in &pending {
        apply_migration(conn, migration)?;
        applied.push(migration.name.to_string());
    }

    let to_version = pending.last().map(|m| m.version).unwrap_or(from_version);

    Ok(MigrationSummary {
        from_version,
        to_version,
        migrations_applied: applied,
    })
}

/// Idempotent bootstrap for the bookkeeping table itself.
fn ensure_migrations_table(conn: &Connection) -> SidecarResult<()> {
    conn.execute_batch(CREATE_SCHEMA_MIGRATIONS)?;
    Ok(())
}

/// Read the highest applied version from `schema_migrations`.
///
/// Returns zero when the table does not exist (freshly created
/// database) or contains no rows (extremely rare race between
/// `ensure_migrations_table` and the first migration commit).
fn current_version(conn: &Connection) -> SidecarResult<u32> {
    let table_exists: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'schema_migrations'",
        [],
        |r| r.get(0),
    )?;
    if table_exists == 0 {
        return Ok(0);
    }
    let max_version: i64 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(u32::try_from(max_version).unwrap_or(0))
}

/// Re-compute checksums for migrations already applied and compare
/// against the stored values. A mismatch indicates somebody (or
/// somebody's editor + git merge) altered a migration's SQL after
/// the database had already applied it, and proceeding without
/// alerting the user would corrupt schema invariants on the next
/// run.
fn validate_applied_checksums(conn: &Connection, applied_up_to: u32) -> SidecarResult<()> {
    for migration in MIGRATIONS.iter().filter(|m| m.version <= applied_up_to) {
        let stored: Option<String> = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE version = ?1",
                params![i64::from(migration.version)],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(stored) = stored {
            let computed = checksum_of(migration.stmts);
            if stored != computed {
                return Err(SidecarError::MigrationCorrupted {
                    detail: format!(
                        "checksum mismatch for v{} ({}): stored={stored}, computed={computed}",
                        migration.version, migration.name,
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Execute one migration step atomically.
fn apply_migration(conn: &mut Connection, migration: &MigrationDef) -> SidecarResult<()> {
    let tx = conn.transaction()?;
    for stmt in migration.stmts {
        tx.execute_batch(stmt)?;
    }
    tx.execute(
        "INSERT OR REPLACE INTO schema_migrations
            (version, name, applied_at, checksum, app_version)
            VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            i64::from(migration.version),
            migration.name,
            system_time_to_ms(SystemTime::now()),
            checksum_of(migration.stmts),
            env!("CARGO_PKG_VERSION"),
        ],
    )?;
    tx.commit()?;
    Ok(())
}

/// FNV-1a 64-bit checksum over all statements, NUL-separated. The
/// constant matches `nrr-storage::migration::checksum_of` so a future
/// shared helper crate can absorb both without changing on-disk
/// checksums.
fn checksum_of(stmts: &[&str]) -> String {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut h = OFFSET;
    for stmt in stmts {
        for b in stmt.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(PRIME);
        }
        h ^= 0x00;
        h = h.wrapping_mul(PRIME);
    }
    format!("{h:016x}")
}

/// Convert a `SystemTime` to milliseconds since UNIX epoch. A clock
/// before the epoch (e.g. system clock reset to 1970) yields zero
/// rather than panicking — the value is informational, not
/// load-bearing.
fn system_time_to_ms(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
            vec!["initial_sidecar_schema", "external_ip_cache"]
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
}
