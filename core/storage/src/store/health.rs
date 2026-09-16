use super::*;

impl StorageHealthChecker for SqliteCacheStore {
    fn check_health(&self) -> StorageResult<StorageHealthStatus> {
        let conn = self.conn.borrow();
        let now = SystemTime::now();

        // Schema version — always present after migration.
        let schema_version: Option<i64> = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;

        let last_migration_ms: Option<i64> = conn
            .query_row("SELECT MAX(applied_at) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        // cache_metadata singleton — may not exist on a fresh DB before the first
        // clear/rebuild, so fall back to NULL for all optional columns.
        let meta: Option<(Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT last_cleanup_at, last_rebuild_at FROM cache_metadata WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db_err)?;

        let (last_cleanup_ms, last_rebuild_ms) = meta.unwrap_or((None, None));

        let cache_db = DbHealthStatus {
            path_exists: true,
            schema_version: schema_version.map(|v| v as u32),
            last_migration_at: last_migration_ms.map(ms_to_system_time),
            last_integrity_check_at: None, // populated by the integrity flow
            last_cleanup_at: last_cleanup_ms.map(ms_to_system_time),
            // Propagate cache rebuild timestamp from the singleton row.
            // `None` means the cache has not been explicitly rebuilt or
            // DNS-refreshed yet (fresh install or no warm-up writes).
            last_rebuild_at: last_rebuild_ms.map(ms_to_system_time),
            overall: OverallHealthState::Healthy,
        };

        Ok(StorageHealthStatus {
            cache_db,
            state_db: DbHealthStatus {
                path_exists: true,
                schema_version: None,
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            checked_at: now,
        })
    }
}

impl StorageHealthChecker for SqliteStateStore {
    fn check_health(&self) -> StorageResult<StorageHealthStatus> {
        let conn = self.conn.borrow();
        let now = SystemTime::now();

        let schema_version: Option<i64> = conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;

        let last_migration_ms: Option<i64> = conn
            .query_row("SELECT MAX(applied_at) FROM schema_migrations", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        let last_check_ms: Option<i64> = conn
            .query_row("SELECT MAX(checked_at) FROM integrity_log", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(db_err)?
            .flatten();

        let state_db = DbHealthStatus {
            path_exists: true,
            schema_version: schema_version.map(|v| v as u32),
            last_migration_at: last_migration_ms.map(ms_to_system_time),
            last_integrity_check_at: last_check_ms.map(ms_to_system_time),
            last_cleanup_at: None,
            last_rebuild_at: None,
            overall: OverallHealthState::Healthy,
        };

        Ok(StorageHealthStatus {
            cache_db: DbHealthStatus {
                path_exists: true,
                schema_version: None,
                last_migration_at: None,
                last_integrity_check_at: None,
                last_cleanup_at: None,
                last_rebuild_at: None,
                overall: OverallHealthState::Healthy,
            },
            state_db,
            checked_at: now,
        })
    }
}
