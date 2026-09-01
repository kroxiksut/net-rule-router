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
    "local_network_rules",
    "refusing_anchors",
    "block_notice_journal",
];

/// Principals this database holds ANY state for, excluding the shared
/// baseline. Full reset reads it to know whose data it is about to erase; the
/// count is all it needs, so nothing here is resolved to a user name.
///
/// The union spans the revision history AND every table in [`PURGED_TABLES`],
/// because in the Free model a `revisions` row appears only at the first rules
/// edit. Reading `revisions` alone missed the user who bound adapters,
/// configured the kill switch or answered the local-network questions but
/// never touched a rule: their state survived a "reset everything", and the
/// "N other users lose data" count shown before the reset was short by however
/// many such users there were.
pub fn principals_with_state(conn: &Connection) -> StorageResult<Vec<String>> {
    let mut selects = vec!["SELECT principal AS p FROM revisions".to_string()];
    selects.extend(
        PURGED_TABLES
            .iter()
            .map(|t| format!("SELECT sid AS p FROM {t}")),
    );
    let sql = format!(
        "SELECT DISTINCT p FROM ({}) ORDER BY p ASC",
        selects.join(" UNION ALL ")
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| StorageError::Internal(format!("principals_with_state prepare: {e}")))?;
    let principals = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| StorageError::Internal(format!("principals_with_state query: {e}")))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| StorageError::Internal(format!("principals_with_state collect: {e}")))?;
    Ok(principals
        .into_iter()
        .filter(|p| p != BASELINE_PRINCIPAL && !p.is_empty())
        .collect())
}

/// The rules the SERVICE holds for one principal: its revision history, the
/// pointer at the active one, and any unconsumed mutation tokens. Deliberately
/// outside [`PURGED_TABLES`] — the ordinary auxiliary purge must never drop a
/// user's rules, and only a full reset asks for this.
///
/// Deletion order follows the foreign key: the pointer references the
/// revision, so it goes first. Returns rows deleted.
pub fn purge_principal_rules(conn: &mut Connection, principal: &str) -> StorageResult<u64> {
    if principal.is_empty() {
        return Err(StorageError::Internal(
            "purge_principal_rules: empty principal".into(),
        ));
    }
    if principal == BASELINE_PRINCIPAL {
        return Err(StorageError::Internal(
            "purge_principal_rules: refusing to purge the shared baseline".into(),
        ));
    }
    let tx = conn
        .transaction()
        .map_err(|e| StorageError::Internal(format!("principal rules purge begin: {e}")))?;
    let mut rows: u64 = 0;
    for sql in [
        "DELETE FROM active_revision_pointer WHERE principal = ?1",
        "DELETE FROM revisions WHERE principal = ?1",
        "DELETE FROM mutation_tokens WHERE principal = ?1",
    ] {
        let deleted = tx
            .execute(sql, [principal])
            .map_err(|e| StorageError::Internal(format!("principal rules purge: {e}")))?;
        rows = rows.saturating_add(deleted as u64);
    }
    tx.commit()
        .map_err(|e| StorageError::Internal(format!("principal rules purge commit: {e}")))?;
    Ok(rows)
}

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
        conn.execute(
            "INSERT INTO local_network_rules (sid, cidr, allow, origin, updated_at)
             VALUES (?1, '10.0.2.0/24', 1, 'manual', 1)",
            params![sid],
        )
        .expect("local_network_rules");
        conn.execute(
            "INSERT INTO refusing_anchors (sid, hostname, marked_at) VALUES (?1, 'chatgpt.com', 1)",
            params![sid],
        )
        .expect("refusing_anchors");
        conn.execute(
            "INSERT INTO block_notice_journal
                 (sid, raised_at, destination, app, reason, attempts)
             VALUES (?1, 1, 'blocked.example', 'app.exe', 'blocked-by-rule', 2)",
            params![sid],
        )
        .expect("block_notice_journal");
    }

    fn row_count(conn: &Connection, table: &str, sid: &str) -> i64 {
        conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE sid = ?1"),
            params![sid],
            |r| r.get(0),
        )
        .expect("count")
    }

    /// A user who bound adapters or answered a local-network question but
    /// never edited a rule has no `revisions` row. Enumerating principals from
    /// that table alone skipped them entirely: their auxiliary state survived
    /// "reset everything", and the warning that counts affected users was short.
    #[test]
    fn a_principal_with_only_auxiliary_state_is_still_listed() {
        let conn = migrated_conn();
        seed_sid(&conn, "S-NO-RULES");
        let listed = principals_with_state(&conn).expect("list");
        assert_eq!(listed, vec!["S-NO-RULES".to_string()]);
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

    /// One principal's rules go, the other's stay — a full reset is per user,
    /// and the auxiliary purge alone must leave both sets standing.
    #[test]
    fn the_rules_purge_takes_one_principals_revisions_and_nobody_elses() {
        let mut conn = migrated_conn();
        for principal in ["S-A", "S-B"] {
            conn.execute(
                "INSERT INTO revisions (principal, revision_id, content_hash, rules_json, status,                  source, correlation_id, created_at)                  VALUES (?1, ?2, 'hash', '{}', 'active', 'gui-rules-edit', 'corr', 1)",
                params![principal, format!("rev-{principal}")],
            )
            .expect("revision");
            conn.execute(
                "INSERT INTO active_revision_pointer (principal, revision_id, activated_at)                  VALUES (?1, ?2, 1)",
                params![principal, format!("rev-{principal}")],
            )
            .expect("pointer");
        }

        // The auxiliary purge leaves the rules alone…
        purge_principal_data(&mut conn, "S-A").expect("aux purge");
        assert_eq!(revision_count(&conn, "S-A"), 1);

        // …the full reset takes them.
        let rows = purge_principal_rules(&mut conn, "S-A").expect("rules purge");
        assert_eq!(rows, 2, "one revision + one pointer");
        assert_eq!(revision_count(&conn, "S-A"), 0);
        assert_eq!(revision_count(&conn, "S-B"), 1);
    }

    #[test]
    fn the_rules_purge_refuses_the_shared_baseline() {
        let mut conn = migrated_conn();
        assert!(purge_principal_rules(&mut conn, BASELINE_PRINCIPAL).is_err());
        assert!(purge_principal_rules(&mut conn, "").is_err());
    }

    fn revision_count(conn: &Connection, principal: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM revisions WHERE principal = ?1",
            params![principal],
            |r| r.get(0),
        )
        .expect("count")
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
    fn revision_history_is_never_in_the_auxiliary_scope() {
        for table in PURGED_TABLES {
            assert!(!matches!(
                *table,
                "revisions" | "active_revision_pointer" | "mutation_tokens"
            ));
        }
    }
}
