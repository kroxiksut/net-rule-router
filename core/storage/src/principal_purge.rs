//! Full per-principal auxiliary-state purge — the storage side of "full reset".
//!
//! Scope: every `sid`-keyed table except rules revision history (its own
//! dedicated reset path already runs alongside this), the shared FQDN/IP
//! cache (machine-wide), and audit (never touched by user cleanup).

use rusqlite::Connection;

use crate::error::{StorageError, StorageResult};
use crate::schema::BASELINE_PRINCIPAL;

/// Tables this purge touches. Order is stable for readable `.dump`/log
/// output; no FK constraints bind them to each other.
const PURGED_TABLES: &[&str] = &[
    "route_bindings",
    "behavior_mode",
    "secondary_block_policy",
    "route_link_provider_apps",
    "migration_state",
    "routing_pause_state",
    "auto_rule_dismissals",
    "auto_rule_pending_candidates",
    "auto_rule_evidence",
    "block_notice_mutes",
];

/// Outcome of [`purge_principal_data`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalPurgeSummary {
    pub principal: String,
    /// Total rows deleted across every table.
    pub rows_deleted: u64,
    /// How many of the [`PURGED_TABLES`] held at least one row.
    pub tables_touched: usize,
    /// Per-table row counts, same order as [`PURGED_TABLES`].
    pub per_table: Vec<(&'static str, u64)>,
}

/// Deletes every row belonging to `principal` across [`PURGED_TABLES`], in
/// one transaction. Idempotent; never touches another principal's rows.
/// Refuses the baseline sentinel — none of these tables ever hold baseline
/// rows, so a caller asking for it is a bug, not a legitimate case.
pub fn purge_principal_data(
    conn: &mut Connection,
    principal: &str,
) -> StorageResult<PrincipalPurgeSummary> {
    if principal.is_empty() {
        return Err(StorageError::Internal(
            "purge_principal_data: empty principal".into(),
        ));
    }
    if principal == BASELINE_PRINCIPAL {
        return Err(StorageError::Internal(
            "purge_principal_data: refusing to purge the baseline principal".into(),
        ));
    }

    let tx = conn
        .transaction()
        .map_err(|e| StorageError::Internal(format!("principal purge begin: {e}")))?;

    let mut per_table = Vec::with_capacity(PURGED_TABLES.len());
    let mut rows_deleted: u64 = 0;
    for table in PURGED_TABLES {
        let sql = format!("DELETE FROM {table} WHERE sid = ?1");
        let deleted = tx
            .execute(&sql, [principal])
            .map_err(|e| StorageError::Internal(format!("principal purge {table}: {e}")))?
            as u64;
        per_table.push((*table, deleted));
        rows_deleted += deleted;
    }

    tx.commit()
        .map_err(|e| StorageError::Internal(format!("principal purge commit: {e}")))?;

    let tables_touched = per_table.iter().filter(|(_, n)| *n > 0).count();
    Ok(PrincipalPurgeSummary {
        principal: principal.to_string(),
        rows_deleted,
        tables_touched,
        per_table,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::SqliteMigrationRunner;
    use crate::repository::MigrationRunner;
    use rusqlite::params;

    fn migrated_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory db");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        runner.into_connection()
    }

    fn seed_sid(conn: &Connection, sid: &str) {
        conn.execute(
            "INSERT INTO route_bindings (sid, role, stable_id, display_name, user_confirmed, updated_at, binding_source)
             VALUES (?1, 'primary', 'iface-1', 'Ethernet', 1, 1, 'user-assigned')",
            params![sid],
        ).expect("route_bindings");
        conn.execute(
            "INSERT INTO behavior_mode (sid, mode, updated_at) VALUES (?1, 'prefer-primary', 1)",
            params![sid],
        )
        .expect("behavior_mode");
        conn.execute(
            "INSERT INTO secondary_block_policy (sid, block_secondary_when_unavailable, updated_at)
             VALUES (?1, 0, 1)",
            params![sid],
        )
        .expect("secondary_block_policy");
        conn.execute(
            "INSERT INTO route_link_provider_apps (sid, role, exe_path, updated_at)
             VALUES (?1, 'secondary', 'C:\\vpn.exe', 1)",
            params![sid],
        )
        .expect("route_link_provider_apps");
        conn.execute(
            "INSERT INTO migration_state (sid, migration_id, completed_at) VALUES (?1, 'legacy_preferences_v1', 1)",
            params![sid],
        ).expect("migration_state");
        conn.execute(
            "INSERT INTO routing_pause_state (sid, paused, updated_at) VALUES (?1, 0, 1)",
            params![sid],
        )
        .expect("routing_pause_state");
        conn.execute(
            "INSERT INTO auto_rule_dismissals (sid, candidate_id, anchor, proposed_match, dismissed_at, dto_json)
             VALUES (?1, 'cand-1', 'example.com', 'cdn.example.com', 1, '')",
            params![sid],
        )
        .expect("auto_rule_dismissals");
        conn.execute(
            "INSERT INTO auto_rule_pending_candidates (sid, candidate_id, route, match_kind, dto_json, parked_at)
             VALUES (?1, 'cand-2', 'secondary', 'suffix', '{}', 1)",
            params![sid],
        )
        .expect("auto_rule_pending_candidates");
        conn.execute(
            "INSERT INTO auto_rule_evidence (sid, snapshot_json, updated_at)
             VALUES (?1, '{}', 1)",
            params![sid],
        )
        .expect("auto_rule_evidence");
        conn.execute(
            "INSERT INTO block_notice_mutes (sid, scope_kind, scope_value, updated_at)
             VALUES (?1, 'host', 'blocked.example', 1)",
            params![sid],
        )
        .expect("block_notice_mutes");
    }

    fn row_count(conn: &Connection, table: &str, sid: &str) -> i64 {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE sid = ?1"),
            params![sid],
            |r| r.get(0),
        )
        .expect("count")
    }

    #[test]
    fn purges_every_seeded_table_for_the_caller() {
        let mut conn = migrated_conn();
        seed_sid(&conn, "S-A");
        let summary = purge_principal_data(&mut conn, "S-A").expect("purge");
        assert_eq!(summary.tables_touched, PURGED_TABLES.len());
        assert_eq!(summary.rows_deleted, PURGED_TABLES.len() as u64);
        for table in PURGED_TABLES {
            assert_eq!(row_count(&conn, table, "S-A"), 0, "{table} not cleared");
        }
    }

    #[test]
    fn a_second_sids_rows_survive_byte_for_byte() {
        let mut conn = migrated_conn();
        seed_sid(&conn, "S-A");
        seed_sid(&conn, "S-B");
        purge_principal_data(&mut conn, "S-A").expect("purge A");

        for table in PURGED_TABLES {
            assert_eq!(
                row_count(&conn, table, "S-B"),
                1,
                "{table}: S-B's row must be untouched by S-A's purge"
            );
        }
        // Row-for-row, not just counts: the exact binding survives.
        let stable_id: String = conn
            .query_row(
                "SELECT stable_id FROM route_bindings WHERE sid = 'S-B'",
                [],
                |r| r.get(0),
            )
            .expect("S-B binding");
        assert_eq!(stable_id, "iface-1");
        let mode: String = conn
            .query_row(
                "SELECT mode FROM behavior_mode WHERE sid = 'S-B'",
                [],
                |r| r.get(0),
            )
            .expect("S-B behavior mode");
        assert_eq!(mode, "prefer-primary");
    }

    #[test]
    fn calling_twice_is_a_harmless_no_op_the_second_time() {
        let mut conn = migrated_conn();
        seed_sid(&conn, "S-A");
        purge_principal_data(&mut conn, "S-A").expect("first purge");
        let second = purge_principal_data(&mut conn, "S-A").expect("second purge");
        assert_eq!(second.rows_deleted, 0);
        assert_eq!(second.tables_touched, 0);
    }

    #[test]
    fn refuses_the_baseline_sentinel() {
        let mut conn = migrated_conn();
        let err = purge_principal_data(&mut conn, BASELINE_PRINCIPAL).expect_err("must refuse");
        assert!(matches!(err, StorageError::Internal(_)));
    }

    #[test]
    fn refuses_an_empty_principal() {
        let mut conn = migrated_conn();
        assert!(purge_principal_data(&mut conn, "").is_err());
    }

    #[test]
    fn the_shared_fqdn_ip_cache_is_never_in_scope() {
        // Documents the boundary: none of the purged tables is a cache
        // table (the cache lives in a separate database file entirely).
        for table in PURGED_TABLES {
            assert!(!matches!(
                *table,
                "hostnames"
                    | "ip_addresses"
                    | "hostname_ip_resolutions"
                    | "shared_ip_direct_hosts"
                    | "negative_cache"
                    | "lookup_events"
            ));
        }
    }

    #[test]
    fn revision_history_is_never_in_scope() {
        for table in PURGED_TABLES {
            assert!(!matches!(
                *table,
                "revisions" | "active_revision_pointer" | "mutation_tokens"
            ));
        }
    }
}
