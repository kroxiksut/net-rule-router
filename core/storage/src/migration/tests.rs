use super::*;
use crate::repository::MigrationRunner;

fn cache_runner(dir: &tempfile::TempDir) -> SqliteMigrationRunner {
    let path = dir.path().join("cache.db");
    let conn = open_connection(&path).expect("open_connection");
    SqliteMigrationRunner::for_cache_db(conn)
}

fn state_runner(dir: &tempfile::TempDir) -> SqliteMigrationRunner {
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open_connection");
    SqliteMigrationRunner::for_state_db(conn)
}

// ── open_connection ───────────────────────────────────────────────────────

#[test]
fn open_connection_enables_wal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let conn = open_connection(&path).expect("connect");
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("pragma");
    assert_eq!(mode, "wal");
}

#[test]
fn open_connection_enables_foreign_keys() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let conn = open_connection(&path).expect("connect");
    let fk: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .expect("pragma");
    assert_eq!(fk, 1);
}

#[test]
fn open_connection_reopen_is_consistent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let _ = open_connection(&path).expect("first open");
    let conn2 = open_connection(&path).expect("reopen");
    // WAL and FK still enabled on second open
    let mode: String = conn2
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .expect("mode");
    assert_eq!(mode, "wal");
}

// ── schema version on fresh db ────────────────────────────────────────────

#[test]
fn version_zero_before_migrations() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    assert_eq!(runner.current_schema_version().expect("version"), 0);
}

#[test]
fn version_zero_when_migrations_table_absent() {
    // current_schema_version must return 0 even if schema_migrations was
    // never created (e.g. called before run_pending_migrations).
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    assert_eq!(runner.current_schema_version().expect("version"), 0);
}

// ── cache DB migrations ───────────────────────────────────────────────────

#[test]
fn run_cache_migrations_empty_db() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);

    let s = runner.run_pending_migrations().expect("migrate");
    assert_eq!(s.from_version, 0);
    assert_eq!(s.to_version, 4);
    assert_eq!(
        s.migrations_applied,
        [
            "initial_cache_schema",
            "add_shared_ip_census",
            "add_fake_ip_bindings",
            "add_shared_ip_census_primary_ruled"
        ]
    );
}

#[test]
fn cache_migration_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);

    runner.run_pending_migrations().expect("first run");
    let s = runner.run_pending_migrations().expect("second run");
    assert_eq!(s.from_version, 4);
    assert_eq!(s.to_version, 4);
    assert!(
        s.migrations_applied.is_empty(),
        "no migrations on second run"
    );
}

#[test]
fn cache_schema_version_is_4_after_migration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    runner.run_pending_migrations().expect("migrate");
    assert_eq!(runner.current_schema_version().expect("version"), 4);
}

// ── state DB migrations ───────────────────────────────────────────────────

#[test]
fn run_state_migrations_empty_db() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = state_runner(&dir);

    let s = runner.run_pending_migrations().expect("migrate");
    assert_eq!(s.from_version, 0);
    // v1..v4 (baseline) + v5 (per-SID routing)
    // + v6 (rules revisions)
    // + v7 (settings + pause state)
    // + v8 (service stability config)
    // + v9 (verbose_logging column)
    // + v10 (explain_snapshots table)
    // + v11 (revisions.row_hmac column)
    // + v12 (per-principal revisions reset)
    // + v13 (conn-trace toggles on service_stability_config)
    // + v14 (rule-scope on service_stability_config)
    // + v15 (kill-switch fail-closed on secondary_block_policy)
    // + v16 (multi-protocol kill-switch on secondary_block_policy)
    // + v17 (routing_stop_policy on service_stability_config — persist-on-stop)
    // + v18 (log_retention_config table — log/audit retention)
    // + v19 (cache_refresh_interval on service_stability_config)
    // + v20 (include_subdomains on secondary_block_policy)
    // + v21 (shared_ip_policy on secondary_block_policy)
    // + v22 (known_stable_ids on route_bindings)
    // + v23 (kill_switch_block_all on secondary_block_policy)
    // + v24 (enforcement_mode on service_stability_config — Mode B)
    // + v25 (secondary_liveness_window_secs on service_stability_config)
    // + v26 (kill_switch_enabled on secondary_block_policy — master toggle)
    // + v27 (allow_dns_over_primary on secondary_block_policy — DNS opt-in)
    // + v28 (mode_a_coverage_strategy + resolve_hosts_bypass on secondary_block_policy)
    // + v29 (app_pattern_resolutions + vpn_bootstrap_endpoints tables)
    // + v30 (route_link_provider_apps table)
    // + v31 (doh_lockdown fields + doh_resolver_entries table)
    // + v32 (browser_history_auto_seed on secondary_block_policy)
    // + v33 (kill_switch_strict_shared_ips on secondary_block_policy)
    // + v34 (fake_ip_enabled on service_stability_config)
    // + v35 (traffic_stats_settings table)
    // + v36 (dns_via_secondary on service_stability_config)
    // + v37 (fake_ip_heal_exclusions table — VPN self-heal persistence)
    // + v38 (dns_fast_answers on service_stability_config)
    // + v39 (fake_ip_udp_relay on service_stability_config)
    // + v40 (fake_ip_instant_rst on service_stability_config)
    // + v41 (vpn_client_apps table — role-verified VPN client persistence)
    // + v42 (auto_rules_mode on secondary_block_policy)
    // + v43 (auto_rule_dismissals table — refused companion suggestions)
    // + v44 (app_observed_destinations table — persisted app destinations)
    // + v45 (allow_user_rule_edits on service_stability_config)
    // + v46 (auto_rules_eager_delivery_names on secondary_block_policy)
    // + v47 (auto_rule_pending_candidates table — durable pending suggestions)
    // + v48 (auto_rule_dismissals.dto_json — the refused offer, kept verbatim)
    // + v49 (block_notice_mutes table — durable "do not show" choices)
    // + v50 (isp_block_candidates_enabled on service_stability_config)
    assert_eq!(s.to_version, 62);
    assert_eq!(
        s.migrations_applied,
        [
            "initial_state_schema",
            "add_revision_integrity_hashes",
            "add_security_alerts",
            "add_apply_snapshots",
            "add_per_sid_routing_policy",
            "add_rules_revisions",
            "add_settings_and_pause_state",
            "add_service_stability_config",
            "add_verbose_logging_to_service_stability_config",
            "add_explain_snapshots",
            "add_revisions_row_hmac",
            "reset_revisions_for_per_principal",
            "add_conn_trace_toggles_to_service_stability_config",
            "add_rule_scope_to_service_stability_config",
            "add_kill_switch_fail_closed_to_secondary_block_policy",
            "add_kill_switch_protocols_to_secondary_block_policy",
            "add_routing_stop_policy_to_service_stability_config",
            "add_log_retention_config",
            "add_cache_refresh_interval_to_service_stability_config",
            "add_include_subdomains_to_secondary_block_policy",
            "add_shared_ip_policy_to_secondary_block_policy",
            "add_known_stable_ids_to_route_bindings",
            "add_kill_switch_block_all_to_secondary_block_policy",
            "add_enforcement_mode_to_service_stability_config",
            "add_secondary_liveness_window_to_service_stability_config",
            "add_kill_switch_enabled_to_secondary_block_policy",
            "add_allow_dns_over_primary_to_secondary_block_policy",
            "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
            "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
            "add_route_link_provider_apps",
            "add_doh_lockdown",
            "add_browser_history_auto_seed",
            "add_kill_switch_strict_shared_ips",
            "add_fake_ip_enabled",
            "add_traffic_stats_settings",
            "add_dns_via_secondary",
            "add_fake_ip_heal_exclusions",
            "add_dns_fast_answers",
            "add_fake_ip_udp_relay",
            "add_fake_ip_instant_rst",
            "add_vpn_client_apps",
            "add_auto_rules_mode",
            "add_auto_rule_dismissals",
            "add_app_observed_destinations",
            "add_allow_user_rule_edits",
            "add_auto_rules_eager_delivery_names",
            "add_auto_rule_pending_candidates",
            "add_auto_rule_dismissal_dto",
            "add_block_notice_mutes",
            "add_isp_block_candidates_enabled",
            "widen_block_notice_mute_scopes",
            "add_auto_rule_evidence",
            "add_local_network_rules",
            "add_primary_probe_preferences",
            "add_refusing_anchors",
            "add_block_ipv6_when_protected",
            "add_block_notice_journal",
            "add_local_network_adapter",
            "add_local_networks_auto_accept",
            "drop_legacy_revision_singletons",
            "add_zone_priority_over_ip",
            "sign_active_revision_pointer",
        ]
    );
}

#[test]
fn state_migration_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = state_runner(&dir);

    runner.run_pending_migrations().expect("first run");
    let s = runner.run_pending_migrations().expect("second run");
    assert_eq!(s.from_version, 62);
    assert_eq!(s.to_version, 62);
    assert!(s.migrations_applied.is_empty());
}

/// A runner that knows only the FIRST `count` migrations — the state a
/// database left by an older build is in.
fn state_runner_stopped_at(dir: &tempfile::TempDir, count: usize) -> SqliteMigrationRunner {
    let path = dir.path().join("state.db");
    let conn = open_connection(&path).expect("open_connection");
    SqliteMigrationRunner {
        conn: RefCell::new(conn),
        migrations: &STATE_MIGRATIONS[..count],
        required_tables: STATE_REQUIRED_TABLES,
        required_indexes: STATE_REQUIRED_INDEXES,
        backup_policy: None,
    }
}

/// Every version an installed build could have left behind must upgrade to
/// the current schema.
///
/// `run_state_migrations_empty_db` only ever walks 0 → latest, which is the
/// one path a developer's machine takes. A user upgrading from build N
/// starts at N, and a migration that quietly assumes a table introduced
/// later fails only for them — after the release. This walks all of them.
#[test]
fn every_intermediate_state_version_upgrades_to_the_current_schema() {
    for stop_at in 1..=STATE_MIGRATIONS.len() {
        let dir = tempfile::tempdir().expect("temp dir");
        let older = state_runner_stopped_at(&dir, stop_at);
        let partial = older
            .run_pending_migrations()
            .unwrap_or_else(|e| panic!("migrating an empty db to v{stop_at}: {e}"));
        assert_eq!(
            partial.to_version, stop_at as u32,
            "the prefix runner must stop exactly where it was told"
        );
        drop(older);

        let current = state_runner(&dir);
        let rest = current
            .run_pending_migrations()
            .unwrap_or_else(|e| panic!("upgrading a v{stop_at} database: {e}"));
        assert_eq!(
            rest.from_version, stop_at as u32,
            "the upgrade must start from the version the older build left"
        );
        assert_eq!(rest.to_version, STATE_MIGRATIONS.len() as u32);
        let verified = current
            .verify_schema()
            .unwrap_or_else(|e| panic!("verifying after an upgrade from v{stop_at}: {e}"));
        assert!(
            verified.is_ok(),
            "schema after upgrading from v{stop_at} is incomplete: {verified:?}"
        );
    }
}

/// Positive control for the walk above: the prefix runner really does stop
/// short, so a green matrix is not a matrix of full migrations.
#[test]
fn the_prefix_runner_leaves_the_schema_incomplete() {
    let dir = tempfile::tempdir().expect("temp dir");
    let older = state_runner_stopped_at(&dir, 1);
    older.run_pending_migrations().expect("migrate to v1");
    let verified = older.verify_schema().expect("verify");
    assert!(
        !verified.is_ok(),
        "v1 alone cannot satisfy the current schema, or this test proves nothing"
    );
}

// ── verify_schema ─────────────────────────────────────────────────────────

#[test]
fn verify_cache_schema_after_migration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    runner.run_pending_migrations().expect("migrate");

    let v = runner.verify_schema().expect("verify");
    assert!(v.is_ok(), "cache schema verification failed: {v:?}");
    assert_eq!(v.version, 4);
}

#[test]
fn verify_state_schema_after_migration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = state_runner(&dir);
    runner.run_pending_migrations().expect("migrate");

    let v = runner.verify_schema().expect("verify");
    assert!(v.is_ok(), "state schema verification failed: {v:?}");
    // through v50 (isp_block_candidates_enabled on service_stability_config)
    assert_eq!(v.version, 62);
}

#[test]
fn verify_schema_fails_before_migration() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    // No migration run — required tables are missing.
    let v = runner.verify_schema().expect("verify");
    assert!(!v.required_tables_present);
}

// ── unsupported future schema version ─────────────────────────────────────

#[test]
fn unsupported_future_schema_returns_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cache.db");

    // Seed a "future" version directly.
    {
        let conn = open_connection(&path).expect("open");
        conn.execute_batch(CREATE_SCHEMA_MIGRATIONS).expect("setup");
        conn.execute(
            "INSERT INTO schema_migrations
                 (version, name, applied_at, checksum, app_version)
                 VALUES (99, 'future', 0, 'deadbeef', '99.0.0')",
            [],
        )
        .expect("insert future version");
    }

    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    let result = runner.run_pending_migrations();

    assert!(
        matches!(
            result,
            Err(StorageError::UnsupportedSchemaVersion { found: 99, .. })
        ),
        "expected UnsupportedSchemaVersion, got: {result:?}"
    );
}

// ── into_connection ───────────────────────────────────────────────────────

#[test]
fn into_connection_returns_working_connection() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    runner.run_pending_migrations().expect("migrate");

    let conn = runner.into_connection();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
        .expect("query");
    assert_eq!(
        count, 4,
        "schema_migrations must have one row per applied cache migration (v1..v4)"
    );
}

// ── schema_migrations record integrity ────────────────────────────────────

#[test]
fn migration_record_has_correct_version_and_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = cache_runner(&dir);
    runner.run_pending_migrations().expect("migrate");

    let conn = runner.into_connection();
    let (version, name, checksum): (i64, String, String) = conn
        .query_row(
            "SELECT version, name, checksum FROM schema_migrations WHERE version = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query");
    assert_eq!(version, 1);
    assert_eq!(name, "initial_cache_schema");
    assert!(!checksum.is_empty());
}

// ── checksum ─────────────────────────────────────────────────────────────

#[test]
fn checksum_is_deterministic() {
    let stmts: &[&str] = &["CREATE TABLE foo (id INTEGER)", "CREATE INDEX i ON foo(id)"];
    assert_eq!(checksum_of(stmts), checksum_of(stmts));
}

#[test]
fn checksum_is_16_hex_chars() {
    let c = checksum_of(&["SELECT 1"]);
    assert_eq!(c.len(), 16, "FNV-64 hex must be 16 chars");
    assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn checksum_differs_for_different_sql() {
    let a = checksum_of(&["CREATE TABLE foo (id INTEGER)"]);
    let b = checksum_of(&["CREATE TABLE bar (id INTEGER)"]);
    assert_ne!(a, b);
}

#[test]
fn checksum_order_sensitive() {
    let s1: &[&str] = &["AAA", "BBB"];
    let s2: &[&str] = &["BBB", "AAA"];
    assert_ne!(checksum_of(s1), checksum_of(s2));
}

// ── busy_timeout ──────────────────────────────────────────────────────────

#[test]
fn open_connection_sets_busy_timeout_5000ms() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let conn = open_connection(&path).expect("connect");
    // sqlite3_busy_timeout() sets the PRAGMA value — verify it was applied.
    let ms: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
        .expect("pragma");
    assert_eq!(ms, 5_000, "busy_timeout must be 5000 ms baseline");
}

/// How many `.db` files sit in the runner's own backup directory.
fn migration_backups(db_path: &Path) -> usize {
    let dir = db_path
        .parent()
        .expect("parent")
        .join("backups")
        .join("migrations");
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("db"))
                .count()
        })
        .unwrap_or(0)
}

#[test]
fn an_upgrade_of_the_state_db_is_snapshotted_first() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_service_state.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("migrate");
    assert_eq!(
        migration_backups(&path),
        0,
        "a database being CREATED has nothing to lose — no snapshot",
    );

    runner
        .snapshot_before_migrating(1, 2)
        .expect("snapshot an existing database");
    assert_eq!(
        migration_backups(&path),
        1,
        "an upgrade of an existing database is snapshotted",
    );
}

#[test]
fn a_rebuildable_database_is_not_snapshotted() {
    // Losing the cache costs a rebuild, not data, so it carries no policy —
    // and a failed snapshot must never be able to block its migration.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_fqdn_ip_cache.db");
    let conn = open_connection(&path).expect("open");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    assert!(runner.backup_policy.is_none());
    runner.run_pending_migrations().expect("migrate");
    assert_eq!(migration_backups(&path), 0);
}

// ── interrupted migration — transaction atomicity ─────────────────────────

#[test]
fn interrupted_migration_leaves_db_unchanged() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let mut conn = open_connection(&path).expect("open");
    ensure_migrations_table(&conn).expect("bootstrap");

    // A migration whose second statement contains invalid SQL.
    // The first statement must be rolled back together with the second.
    let bad = MigrationDef {
        version: 1,
        name: "bad",
        stmts: &[
            "CREATE TABLE valid_table (id INTEGER)",
            "THIS IS NOT VALID SQL;;;",
        ],
    };
    let result = apply_migration(&mut conn, &bad);
    assert!(result.is_err(), "bad DDL must fail");

    // Transaction must have been rolled back: version is still 0.
    assert_eq!(current_version(&conn).expect("version"), 0);

    // The first DDL statement must also be rolled back.
    let table_present: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='valid_table'",
            [],
            |r| r.get(0),
        )
        .expect("query");
    assert_eq!(
        table_present, 0,
        "partial DDL must be rolled back by transaction"
    );
}

// ── checksum mismatch detection ───────────────────────────────────────────

#[test]
fn migration_checksum_mismatch_detected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("cache.db");

    // Run migrations normally.
    {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_cache_db(conn);
        runner.run_pending_migrations().expect("first run");
    }

    // Corrupt the stored checksum via a direct connection.
    {
        let conn = open_connection(&path).expect("open for corruption");
        conn.execute(
            "UPDATE schema_migrations SET checksum = 'deadbeef00000000' WHERE version = 1",
            [],
        )
        .expect("corrupt checksum");
    }

    // Re-open: run_pending_migrations must detect the mismatch.
    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_cache_db(conn);
    let result = runner.run_pending_migrations();
    assert!(
        matches!(result, Err(StorageError::MigrationFailed { .. })),
        "expected MigrationFailed for checksum mismatch, got: {result:?}"
    );
}

#[test]
fn missing_migration_row_below_the_maximum_is_rejected() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");

    {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("first run");
    }

    // An upgrade that died between two migrations leaves the row of the one
    // that never committed missing while the maximum stays high.
    {
        let conn = open_connection(&path).expect("open for corruption");
        conn.execute("DELETE FROM schema_migrations WHERE version = 2", [])
            .expect("drop history row");
    }

    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    let result = runner.run_pending_migrations();
    let Err(StorageError::MigrationFailed { reason, .. }) = result else {
        panic!("expected MigrationFailed for the history gap, got: {result:?}");
    };
    assert!(
        reason.contains("missing from the applied history"),
        "reason must name the gap, got: {reason}"
    );
}

#[test]
fn complete_history_still_passes_validation() {
    // Positive control for the gap check above: an untouched database must
    // migrate and re-open without complaint.
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");

    for _ in 0..2 {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("clean history");
    }
}

// ── traffic DB — delete + rebuild on open/migration failure ──────────────

#[test]
fn traffic_db_clean_open_reports_no_rebuild() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_traffic_stats.db");

    let opened = open_traffic_connection_or_rebuild(&path).expect("open");
    assert!(opened.rebuilt_reason.is_none(), "fresh DB must not rebuild");
    let version = read_schema_version(&opened.connection).expect("version");
    assert_eq!(version, TRAFFIC_MIGRATIONS.len() as u32);
}

#[test]
fn traffic_db_checksum_mismatch_is_deleted_and_rebuilt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_traffic_stats.db");

    // Create + migrate, then leave a marker row a rebuild must discard.
    {
        let opened = open_traffic_connection_or_rebuild(&path).expect("first open");
        assert!(opened.rebuilt_reason.is_none());
        opened
            .connection
            .execute(
                "INSERT INTO interface_identity (adapter_key, display_name, last_seen)
                     VALUES ('eth0', 'Ethernet', 0)",
                [],
            )
            .expect("marker row");
    }

    // Corrupt the stored migration checksum — simulates the SQL of an
    // already-applied migration changing in place.
    {
        let conn = open_connection(&path).expect("open for corruption");
        conn.execute(
            "UPDATE schema_migrations SET checksum = 'deadbeef00000000' WHERE version = 1",
            [],
        )
        .expect("corrupt checksum");
    }

    // Reopen: the mismatch must trigger delete + rebuild, not a failure.
    let opened = open_traffic_connection_or_rebuild(&path).expect("rebuild open");
    let reason = opened.rebuilt_reason.as_deref().expect("rebuild reported");
    assert!(
        reason.contains("checksum mismatch"),
        "reason must carry the original failure, got: {reason}"
    );

    // Fresh schema: the marker row is gone, the store is fully usable.
    let markers: i64 = opened
        .connection
        .query_row("SELECT COUNT(*) FROM interface_identity", [], |r| r.get(0))
        .expect("query rebuilt DB");
    assert_eq!(markers, 0, "rebuild must discard old data");
    drop(opened);

    // A subsequent open is clean — the rebuilt DB has valid checksums.
    let opened = open_traffic_connection_or_rebuild(&path).expect("clean reopen");
    assert!(opened.rebuilt_reason.is_none());
}

#[test]
fn traffic_db_from_a_newer_build_is_refused_not_erased() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_traffic_stats.db");

    {
        let opened = open_traffic_connection_or_rebuild(&path).expect("first open");
        opened
            .connection
            .execute(
                "INSERT INTO interface_identity (adapter_key, display_name, last_seen)
                     VALUES ('eth0', 'Ethernet', 0)",
                [],
            )
            .expect("marker row");
        // A migration this build knows nothing about — what starting the
        // next release once and then rolling back looks like on disk.
        opened
            .connection
            .execute(
                "INSERT INTO schema_migrations
                     (version, name, applied_at, checksum, app_version)
                     VALUES (99, 'from_the_future', 0, 'aaaaaaaaaaaaaaaa', '99.0')",
                [],
            )
            .expect("future migration row");
    }

    let outcome = open_traffic_connection_or_rebuild(&path).err();
    assert!(
        matches!(outcome, Some(StorageError::UnsupportedSchemaVersion { .. })),
        "a newer schema must be refused, got: {outcome:?}"
    );

    // The point of refusing: the ledger is still there for the build that
    // wrote it.
    let conn = open_connection(&path).expect("reopen");
    let markers: i64 = conn
        .query_row("SELECT COUNT(*) FROM interface_identity", [], |r| r.get(0))
        .expect("query ledger");
    assert_eq!(markers, 1, "refusing must not erase the ledger");
}

#[test]
fn traffic_db_garbage_file_is_deleted_and_rebuilt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_traffic_stats.db");
    std::fs::write(&path, b"this is not a sqlite database").expect("write garbage");
    // A stray sidecar must be removed together with the main file.
    std::fs::write(sidecar_path(&path, "-wal"), b"stale wal").expect("write sidecar");

    let opened = open_traffic_connection_or_rebuild(&path).expect("rebuild open");
    assert!(opened.rebuilt_reason.is_some(), "garbage file must rebuild");
    let version = read_schema_version(&opened.connection).expect("version");
    assert_eq!(version, TRAFFIC_MIGRATIONS.len() as u32);
}

/// The path every installed user takes: a v1 traffic ledger gains the
/// answers table WITHOUT losing a day of history. Editing v1 in place would
/// have failed its checksum and rebuilt the file instead — erasing exactly
/// what the merge question exists to preserve.
#[test]
fn upgrade_traffic_db_from_v1_keeps_the_ledger() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_traffic_stats.db");

    // A database an older binary left behind, with a day of history in it.
    {
        let mut conn = open_connection(&path).expect("open");
        ensure_migrations_table(&conn).expect("bootstrap");
        apply_migration(&mut conn, &TRAFFIC_MIGRATIONS[0]).expect("apply v1");
        conn.execute(
            "INSERT INTO interface_daily_traffic (day, adapter_key, role, in_bytes, out_bytes)
                 VALUES (1, 'eth0', 'primary', 111, 222)",
            [],
        )
        .expect("seed a day");
    }

    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_traffic_db(conn);
    assert_eq!(runner.current_schema_version().expect("before"), 1);
    let summary = runner.run_pending_migrations().expect("upgrade");
    assert_eq!(summary.from_version, 1);
    assert_eq!(summary.to_version, TRAFFIC_MIGRATIONS.len() as u32);
    assert!(runner.verify_schema().expect("verify").is_ok());

    let conn = runner.into_connection();
    let kept: i64 = conn
        .query_row(
            "SELECT in_bytes FROM interface_daily_traffic WHERE adapter_key = 'eth0'",
            [],
            |r| r.get(0),
        )
        .expect("the day must survive the upgrade");
    assert_eq!(kept, 111);
}

// ── incremental state DB upgrades ────────────────────────────────────────

#[test]
fn upgrade_state_db_from_v1_to_v2() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");

    // Simulate a DB created by an older binary: only v1 applied.
    {
        let mut conn = open_connection(&path).expect("open");
        ensure_migrations_table(&conn).expect("bootstrap");
        apply_migration(&mut conn, &STATE_MIGRATIONS[0]).expect("apply v1");
    }

    // New binary: runner must detect v1 and apply v2 + v3.
    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_state_db(conn);

    assert_eq!(runner.current_schema_version().expect("before"), 1);

    let summary = runner.run_pending_migrations().expect("upgrade v1→latest");
    assert_eq!(summary.from_version, 1);
    assert_eq!(summary.to_version, 62);
    assert_eq!(
        summary.migrations_applied,
        [
            "add_revision_integrity_hashes",
            "add_security_alerts",
            "add_apply_snapshots",
            "add_per_sid_routing_policy",
            "add_rules_revisions",
            "add_settings_and_pause_state",
            "add_service_stability_config",
            "add_verbose_logging_to_service_stability_config",
            "add_explain_snapshots",
            "add_revisions_row_hmac",
            "reset_revisions_for_per_principal",
            "add_conn_trace_toggles_to_service_stability_config",
            "add_rule_scope_to_service_stability_config",
            "add_kill_switch_fail_closed_to_secondary_block_policy",
            "add_kill_switch_protocols_to_secondary_block_policy",
            "add_routing_stop_policy_to_service_stability_config",
            "add_log_retention_config",
            "add_cache_refresh_interval_to_service_stability_config",
            "add_include_subdomains_to_secondary_block_policy",
            "add_shared_ip_policy_to_secondary_block_policy",
            "add_known_stable_ids_to_route_bindings",
            "add_kill_switch_block_all_to_secondary_block_policy",
            "add_enforcement_mode_to_service_stability_config",
            "add_secondary_liveness_window_to_service_stability_config",
            "add_kill_switch_enabled_to_secondary_block_policy",
            "add_allow_dns_over_primary_to_secondary_block_policy",
            "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
            "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
            "add_route_link_provider_apps",
            "add_doh_lockdown",
            "add_browser_history_auto_seed",
            "add_kill_switch_strict_shared_ips",
            "add_fake_ip_enabled",
            "add_traffic_stats_settings",
            "add_dns_via_secondary",
            "add_fake_ip_heal_exclusions",
            "add_dns_fast_answers",
            "add_fake_ip_udp_relay",
            "add_fake_ip_instant_rst",
            "add_vpn_client_apps",
            "add_auto_rules_mode",
            "add_auto_rule_dismissals",
            "add_app_observed_destinations",
            "add_allow_user_rule_edits",
            "add_auto_rules_eager_delivery_names",
            "add_auto_rule_pending_candidates",
            "add_auto_rule_dismissal_dto",
            "add_block_notice_mutes",
            "add_isp_block_candidates_enabled",
            "widen_block_notice_mute_scopes",
            "add_auto_rule_evidence",
            "add_local_network_rules",
            "add_primary_probe_preferences",
            "add_refusing_anchors",
            "add_block_ipv6_when_protected",
            "add_block_notice_journal",
            "add_local_network_adapter",
            "add_local_networks_auto_accept",
            "drop_legacy_revision_singletons",
            "add_zone_priority_over_ip",
            "sign_active_revision_pointer",
        ]
    );

    // v2 added an `integrity_hash` column to the `active_revision`
    // singleton; v60 drops that table, so the end state must NOT have it.
    // The chain still has to run through both without error, which is what
    // the migration list above asserts.
    let conn = runner.into_connection();
    let singleton_gone = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'table' AND name IN ('active_revision', 'last_known_good')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .expect("count legacy tables");
    assert_eq!(singleton_gone, 0, "v60 drops both legacy singletons");
}

#[test]
fn upgrade_state_db_from_v2_to_v3() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("state.db");

    // Simulate a DB at v2.
    {
        let mut conn = open_connection(&path).expect("open");
        ensure_migrations_table(&conn).expect("bootstrap");
        apply_migration(&mut conn, &STATE_MIGRATIONS[0]).expect("apply v1");
        apply_migration(&mut conn, &STATE_MIGRATIONS[1]).expect("apply v2");
    }

    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_state_db(conn);

    assert_eq!(runner.current_schema_version().expect("before"), 2);

    let summary = runner.run_pending_migrations().expect("upgrade v2→latest");
    assert_eq!(summary.from_version, 2);
    assert_eq!(summary.to_version, 62);
    assert_eq!(
        summary.migrations_applied,
        [
            "add_security_alerts",
            "add_apply_snapshots",
            "add_per_sid_routing_policy",
            "add_rules_revisions",
            "add_settings_and_pause_state",
            "add_service_stability_config",
            "add_verbose_logging_to_service_stability_config",
            "add_explain_snapshots",
            "add_revisions_row_hmac",
            "reset_revisions_for_per_principal",
            "add_conn_trace_toggles_to_service_stability_config",
            "add_rule_scope_to_service_stability_config",
            "add_kill_switch_fail_closed_to_secondary_block_policy",
            "add_kill_switch_protocols_to_secondary_block_policy",
            "add_routing_stop_policy_to_service_stability_config",
            "add_log_retention_config",
            "add_cache_refresh_interval_to_service_stability_config",
            "add_include_subdomains_to_secondary_block_policy",
            "add_shared_ip_policy_to_secondary_block_policy",
            "add_known_stable_ids_to_route_bindings",
            "add_kill_switch_block_all_to_secondary_block_policy",
            "add_enforcement_mode_to_service_stability_config",
            "add_secondary_liveness_window_to_service_stability_config",
            "add_kill_switch_enabled_to_secondary_block_policy",
            "add_allow_dns_over_primary_to_secondary_block_policy",
            "add_mode_a_coverage_and_hosts_bypass_to_secondary_block_policy",
            "add_app_pattern_resolutions_and_vpn_bootstrap_endpoints",
            "add_route_link_provider_apps",
            "add_doh_lockdown",
            "add_browser_history_auto_seed",
            "add_kill_switch_strict_shared_ips",
            "add_fake_ip_enabled",
            "add_traffic_stats_settings",
            "add_dns_via_secondary",
            "add_fake_ip_heal_exclusions",
            "add_dns_fast_answers",
            "add_fake_ip_udp_relay",
            "add_fake_ip_instant_rst",
            "add_vpn_client_apps",
            "add_auto_rules_mode",
            "add_auto_rule_dismissals",
            "add_app_observed_destinations",
            "add_allow_user_rule_edits",
            "add_auto_rules_eager_delivery_names",
            "add_auto_rule_pending_candidates",
            "add_auto_rule_dismissal_dto",
            "add_block_notice_mutes",
            "add_isp_block_candidates_enabled",
            "widen_block_notice_mute_scopes",
            "add_auto_rule_evidence",
            "add_local_network_rules",
            "add_primary_probe_preferences",
            "add_refusing_anchors",
            "add_block_ipv6_when_protected",
            "add_block_notice_journal",
            "add_local_network_adapter",
            "add_local_networks_auto_accept",
            "drop_legacy_revision_singletons",
            "add_zone_priority_over_ip",
            "sign_active_revision_pointer",
        ]
    );

    // The security_alerts table added by v3 must be queryable.
    let conn = runner.into_connection();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_alerts", [], |r| r.get(0))
        .expect("security_alerts table must exist after v3");
    assert_eq!(count, 0, "fresh security_alerts table must be empty");
}
