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
    assert_eq!(s.to_version, 83);
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
            "drop_isp_block_candidates_enabled",
            "add_short_name_suffix",
            "add_block_notice_launched_by",
            "drop_integrity_log_and_apply_snapshots",
            "verbose_logging_deadline",
            "conn_trace_log_deadline",
            "block_notice_mute_notice_scope",
            "add_app_rules_take_all_addresses",
            "add_doh_lockdown_auto",
            "add_local_dns_suffixes",
            "add_forwarded_outage",
            "add_install_policy",
            "app_destinations_by_principal",
            "add_conn_history_prefs",
            "add_override_grants",
            "vpn_bootstrap_endpoints_by_principal",
            "drop_block_secondary_when_unavailable",
            "leak_protection",
            "add_external_address_auto_check",
            "add_vpn_gateway_confirmations",
            "add_routing_pause_term",
        ]
    );
}

#[test]
fn state_migration_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = state_runner(&dir);

    runner.run_pending_migrations().expect("first run");
    let s = runner.run_pending_migrations().expect("second run");
    assert_eq!(s.from_version, 83);
    assert_eq!(s.to_version, 83);
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
        snapshot_first: false,
    }
}

/// Servers remembered before sets had owners stay machine-wide: the Windows
/// route coordinator still reads that set, and a per-user planner relearns.
#[test]
fn remembered_tunnel_servers_written_before_owners_stay_machine_wide() {
    let dir = tempfile::tempdir().expect("temp dir");
    let older = state_runner_stopped_at(&dir, 77);
    older.run_pending_migrations().expect("migrate to v77");
    older
        .into_connection()
        .execute(
            "INSERT INTO vpn_bootstrap_endpoints (ip, port, protocol, source, learned_at)
             VALUES ('203.0.113.9', NULL, NULL, 'observed', 5)",
            [],
        )
        .expect("legacy row");

    let current = state_runner(&dir);
    current.run_pending_migrations().expect("upgrade");
    let conn = current.into_connection();
    let owner: String = conn
        .query_row(
            "SELECT sid FROM vpn_bootstrap_endpoints WHERE ip = '203.0.113.9'",
            [],
            |r| r.get(0),
        )
        .expect("row survives");
    assert_eq!(owner, "");
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
        let stopped_version = STATE_MIGRATIONS[stop_at - 1].version;
        assert_eq!(
            partial.to_version, stopped_version,
            "the prefix runner must stop exactly where it was told"
        );
        drop(older);

        let current = state_runner(&dir);
        let rest = current
            .run_pending_migrations()
            .unwrap_or_else(|e| panic!("upgrading a v{stop_at} database: {e}"));
        assert_eq!(
            rest.from_version, stopped_version,
            "the upgrade must start from the version the older build left"
        );
        // A version, not a count: a number may be held for a later step.
        assert_eq!(
            rest.to_version,
            STATE_MIGRATIONS.last().map_or(0, |m| m.version)
        );
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
    // through v83 (add_routing_pause_term)
    assert_eq!(v.version, 83);
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
        nrr_sqlite_support::ensure_migrations_table(&conn).expect("setup");
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

// ── shipped checksums ─────────────────────────────────────────────────────

/// Every installed database stores these; a changed value is a database that
/// no longer opens. Pinned from the runner that wrote them.
fn assert_checksums(catalogue: &[MigrationDef], want: &[(u32, &str)]) {
    let got: Vec<(u32, String)> = catalogue
        .iter()
        .map(|m| (m.version, nrr_sqlite_support::checksum(m.stmts)))
        .collect();
    assert_eq!(
        got.len(),
        want.len(),
        "a shipped migration was added or removed"
    );
    for ((v, c), (wv, wc)) in got.iter().zip(want) {
        assert_eq!((*v, c.as_str()), (*wv, *wc), "checksum of v{wv} changed");
    }
}

#[test]
fn shipped_state_checksums_are_unchanged() {
    assert_checksums(
        STATE_MIGRATIONS,
        &[
            (1, "5c7d6449810d10e8"),
            (2, "cb90763b4b17ae7f"),
            (3, "7ef719581a403d7b"),
            (4, "9921e2fb67fcaffc"),
            (5, "1b837fc6f68832ae"),
            (6, "2564c9074e48ff63"),
            (7, "04d78a425b65a806"),
            (8, "e7c634ae6a103ecc"),
            (9, "116ff333a9712fa1"),
            (10, "d893265cf829eb9f"),
            (11, "f1cd4ef8ec8531aa"),
            (12, "829c15dcc565b81b"),
            (13, "8234ed4971bb8491"),
            (14, "1426b2f3de4f00f2"),
            (15, "380e2cf700ec172d"),
            (16, "33c9961b31f0ae80"),
            (17, "c8211d3ff026a3dd"),
            (18, "02df205307726d7e"),
            (19, "b84bdf70cbc3d648"),
            (20, "e17517faed453c4a"),
            (21, "6e71e7371d213e78"),
            (22, "fa9a9ac69dd9fe96"),
            (23, "ea21ea75c0f31a26"),
            (24, "642342d310f39e97"),
            (25, "f866411b8d0a5c98"),
            (26, "f6e1d0ea4185eb22"),
            (27, "4149585e359877ae"),
            (28, "a8151ad3e6410a36"),
            (29, "77036d6c3f65b22a"),
            (30, "026a40e2e6cc8a1f"),
            (31, "c7604d77909da151"),
            (32, "eb612dd0d4656842"),
            (33, "c10875aca697f928"),
            (34, "2e488179d03aa0d3"),
            (35, "12c5eaeb4cf51d63"),
            (36, "dfdd4da51b126be3"),
            (37, "a111a0953c4afa38"),
            (38, "790c71a3d08ccb82"),
            (39, "0c78522c1ffb7843"),
            (40, "b7d01c57015397f0"),
            (41, "eb3fba6ba1fd499b"),
            (42, "e8811a4d2a89945e"),
            (43, "c94d4749163da454"),
            (44, "ff2086cbe0e73269"),
            (45, "ba83f12a4eed81d2"),
            (46, "02e50a760fd324b0"),
            (47, "6dd0c383e220009f"),
            (48, "e4093884f984f269"),
            (49, "40afe93c350f4998"),
            (50, "dbd67552a373ad73"),
            (51, "447a881a85a6f369"),
            (52, "2c36af736aa47a81"),
            (53, "e7f7ddbe4e276a2d"),
            (54, "4041ce40884476d5"),
            (55, "25dc3445c3e52a98"),
            (56, "31be14ea3dfc9a91"),
            (57, "c1cdf11cfb4a9be7"),
            (58, "ed5c9e41bcaf0042"),
            (59, "575ce79a1a54bf54"),
            (60, "77f222e8c2ac9893"),
            (61, "537bf93c7f29504a"),
            (62, "6ae8cb07648df3e0"),
            (63, "41eb0ff19deaef86"),
            (64, "e7f3a008c82a5b09"),
            (65, "05750f96e61bd967"),
            (66, "9ad42c4782705cc2"),
            (67, "64cae489eb8a64b4"),
            (68, "bcd0ffef9e5dccf4"),
            (69, "87c9af11c8f16e73"),
            (70, "9f627d43cf19a4cc"),
            (71, "6f293118d0e60ed3"),
            (72, "7ab90024670f8e0e"),
            (73, "cc82674acb6316ff"),
            (74, "42c87cddcd988877"),
            (75, "dfa2c31391bb2ddf"),
            (76, "855bba352ad44570"),
            (77, "64506a874e24293a"),
            (78, "55f3628ade558fb9"),
            (79, "7ec7548be9eae547"),
            (80, "15846ce1e501ccda"),
            (81, "9e54f68d848b0092"),
            (82, "03594f74243f65a7"),
            (83, "09991a8bfe859891"),
        ],
    );
}

#[test]
fn shipped_conn_history_checksums_are_unchanged() {
    assert_checksums(CONN_HISTORY_MIGRATIONS, &[(1, "97e0b0093353de15")]);
}

#[test]
fn shipped_cache_checksums_are_unchanged() {
    assert_checksums(
        CACHE_MIGRATIONS,
        &[
            (1, "aa93411d21c86bf4"),
            (2, "3391406fc5c00490"),
            (3, "041490419242ec35"),
            (4, "a160c37c152a7687"),
        ],
    );
}

#[test]
fn shipped_traffic_checksums_are_unchanged() {
    assert_checksums(
        TRAFFIC_MIGRATIONS,
        &[(1, "2ead989d39a16a24"), (2, "b6b6152a152ea077")],
    );
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
    assert!(!runner.snapshot_first);
    runner.run_pending_migrations().expect("migrate");
    assert_eq!(migration_backups(&path), 0);
}

// ── interrupted migration — transaction atomicity ─────────────────────────

#[test]
fn interrupted_migration_leaves_db_unchanged() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("t.db");
    let mut conn = open_connection(&path).expect("open");

    // The second step's second statement is invalid: the whole run, the good
    // first step included, must roll back.
    let steps = [
        MigrationDef {
            version: 1,
            name: "good",
            stmts: &["CREATE TABLE good_table (id INTEGER)"],
        },
        MigrationDef {
            version: 2,
            name: "bad",
            stmts: &[
                "CREATE TABLE valid_table (id INTEGER)",
                "THIS IS NOT VALID SQL;;;",
            ],
        },
    ];
    assert!(nrr_sqlite_support::migrate(&mut conn, &steps).is_err());

    assert_eq!(read_schema_version(&conn).expect("version"), 0);
    for table in ["good_table", "valid_table"] {
        assert!(
            !relation_exists(&conn, "table", table),
            "{table} must be rolled back with the failed run"
        );
    }
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

// ── connection-history DB — its own catalogue, rebuilt when damaged ────────

#[test]
fn conn_history_db_opens_clean_with_its_own_schema_and_secure_delete() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_conn_history.db");
    let opened = open_conn_history_connection_or_rebuild(&path).expect("open");
    assert!(opened.rebuilt_reason.is_none());
    let version = read_schema_version(&opened.connection).expect("version");
    assert_eq!(version, CONN_HISTORY_MIGRATIONS.len() as u32);
    let secure: i64 = opened
        .connection
        .query_row("PRAGMA secure_delete", [], |r| r.get(0))
        .expect("pragma");
    assert_eq!(secure, 1, "a cleared history must not linger in free pages");
    let runner = SqliteMigrationRunner::for_conn_history_db(opened.connection);
    assert!(runner.verify_schema().expect("verify").is_ok());
}

#[test]
fn conn_history_db_garbage_file_is_deleted_and_rebuilt() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_conn_history.db");
    std::fs::write(&path, b"this is not a sqlite database").expect("write garbage");
    std::fs::write(sidecar_path(&path, "-wal"), b"stale wal").expect("write sidecar");

    let opened = open_conn_history_connection_or_rebuild(&path).expect("rebuild open");
    assert!(opened.rebuilt_reason.is_some(), "garbage file must rebuild");
    let version = read_schema_version(&opened.connection).expect("version");
    assert_eq!(version, CONN_HISTORY_MIGRATIONS.len() as u32);
}

#[test]
fn conn_history_db_from_a_newer_build_is_refused_not_erased() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("nrr_conn_history.db");
    {
        let opened = open_conn_history_connection_or_rebuild(&path).expect("open");
        opened
            .connection
            .execute(
                "INSERT INTO schema_migrations
                     (version, name, applied_at, checksum, app_version)
                     VALUES (99, 'from_the_future', 0, 'aaaaaaaaaaaaaaaa', '99.0')",
                [],
            )
            .expect("future version");
    }
    let outcome = open_conn_history_connection_or_rebuild(&path).err();
    assert!(
        matches!(outcome, Some(StorageError::UnsupportedSchemaVersion { .. })),
        "a newer schema must be refused, got: {outcome:?}"
    );
    assert!(path.exists(), "a newer file is never deleted");
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
        nrr_sqlite_support::migrate(&mut conn, &TRAFFIC_MIGRATIONS[..1]).expect("apply v1");
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
        nrr_sqlite_support::migrate(&mut conn, &STATE_MIGRATIONS[..1]).expect("apply v1");
    }

    // New binary: runner must detect v1 and apply v2 + v3.
    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_state_db(conn);

    assert_eq!(runner.current_schema_version().expect("before"), 1);

    let summary = runner.run_pending_migrations().expect("upgrade v1→latest");
    assert_eq!(summary.from_version, 1);
    assert_eq!(summary.to_version, 83);
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
            "drop_isp_block_candidates_enabled",
            "add_short_name_suffix",
            "add_block_notice_launched_by",
            "drop_integrity_log_and_apply_snapshots",
            "verbose_logging_deadline",
            "conn_trace_log_deadline",
            "block_notice_mute_notice_scope",
            "add_app_rules_take_all_addresses",
            "add_doh_lockdown_auto",
            "add_local_dns_suffixes",
            "add_forwarded_outage",
            "add_install_policy",
            "app_destinations_by_principal",
            "add_conn_history_prefs",
            "add_override_grants",
            "vpn_bootstrap_endpoints_by_principal",
            "drop_block_secondary_when_unavailable",
            "leak_protection",
            "add_external_address_auto_check",
            "add_vpn_gateway_confirmations",
            "add_routing_pause_term",
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
        nrr_sqlite_support::migrate(&mut conn, &STATE_MIGRATIONS[..2]).expect("apply v1, v2");
    }

    let conn = open_connection(&path).expect("reopen");
    let runner = SqliteMigrationRunner::for_state_db(conn);

    assert_eq!(runner.current_schema_version().expect("before"), 2);

    let summary = runner.run_pending_migrations().expect("upgrade v2→latest");
    assert_eq!(summary.from_version, 2);
    assert_eq!(summary.to_version, 83);
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
            "drop_isp_block_candidates_enabled",
            "add_short_name_suffix",
            "add_block_notice_launched_by",
            "drop_integrity_log_and_apply_snapshots",
            "verbose_logging_deadline",
            "conn_trace_log_deadline",
            "block_notice_mute_notice_scope",
            "add_app_rules_take_all_addresses",
            "add_doh_lockdown_auto",
            "add_local_dns_suffixes",
            "add_forwarded_outage",
            "add_install_policy",
            "app_destinations_by_principal",
            "add_conn_history_prefs",
            "add_override_grants",
            "vpn_bootstrap_endpoints_by_principal",
            "drop_block_secondary_when_unavailable",
            "leak_protection",
            "add_external_address_auto_check",
            "add_vpn_gateway_confirmations",
            "add_routing_pause_term",
        ]
    );

    // The security_alerts table added by v3 must be queryable.
    let conn = runner.into_connection();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM security_alerts", [], |r| r.get(0))
        .expect("security_alerts table must exist after v3");
    assert_eq!(count, 0, "fresh security_alerts table must be empty");
}

/// Remembered destinations from before the owner column survive the upgrade,
/// owned by nobody: no user's store may be seeded from them.
#[test]
fn remembered_destinations_upgrade_without_an_owner() {
    let dir = tempfile::tempdir().expect("temp dir");
    let before = STATE_MIGRATIONS
        .iter()
        .position(|m| m.name == "app_destinations_by_principal")
        .expect("the owner migration is catalogued");
    {
        let older = state_runner_stopped_at(&dir, before);
        older
            .run_pending_migrations()
            .expect("migrate to the previous version");
        let conn = older.into_connection();
        conn.execute(
            "INSERT INTO app_observed_destinations (app_key, ip, learned_at)
             VALUES ('messenger', '203.0.113.1', 1000), ('chat', '203.0.113.2', 2000)",
            [],
        )
        .expect("rows an earlier build wrote");
    }

    let current = state_runner(&dir);
    current.run_pending_migrations().expect("upgrade");
    assert!(current.verify_schema().expect("verify").is_ok());
    let conn = current.into_connection();
    let mut stmt = conn
        .prepare("SELECT sid, app_key, ip, learned_at FROM app_observed_destinations ORDER BY ip")
        .expect("prepare");
    let rows: Vec<(String, String, String, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("rows");
    assert_eq!(
        rows,
        vec![
            (
                String::new(),
                "messenger".into(),
                "203.0.113.1".into(),
                1000
            ),
            (String::new(), "chat".into(), "203.0.113.2".into(), 2000),
        ]
    );
}

/// A v79 database whose policy rows carry the four old leak settings.
fn state_db_before_leak_protection(dir: &tempfile::TempDir) {
    let before = STATE_MIGRATIONS
        .iter()
        .position(|m| m.name == "leak_protection")
        .expect("the leak-protection migration is catalogued");
    let older = state_runner_stopped_at(dir, before);
    older
        .run_pending_migrations()
        .expect("migrate to the previous version");
}

/// One policy row as an earlier build wrote it: `mode` goes to
/// `behavior_mode` (`None` = no row), the rest to `secondary_block_policy`.
struct OldPolicy {
    sid: &'static str,
    mode: Option<&'static str>,
    enabled: i64,
    fail_closed: i64,
    block_all: i64,
    coverage: i64,
}

fn write_old_policy(conn: &Connection, row: &OldPolicy) {
    if let Some(mode) = row.mode {
        conn.execute(
            "INSERT INTO behavior_mode (sid, mode, updated_at) VALUES (?1, ?2, 1)",
            rusqlite::params![row.sid, mode],
        )
        .expect("old mode row");
    }
    conn.execute(
        "INSERT INTO secondary_block_policy
            (sid, updated_at, kill_switch_enabled, kill_switch_fail_closed,
             kill_switch_block_all, mode_a_coverage_strategy, kill_switch_protocols,
             block_ipv6_when_protected)
         VALUES (?1, 1, ?2, ?3, ?4, ?5, 5, 0)",
        rusqlite::params![
            row.sid,
            row.enabled,
            row.fail_closed,
            row.block_all,
            row.coverage
        ],
    )
    .expect("old policy row");
}

/// Every branch of the mapping, on rows shaped like the owner's: the old
/// settings are carried over, never reset, and the strict mode becomes the
/// additional default route.
#[test]
fn old_leak_settings_map_onto_one_choice() {
    use crate::route_bindings::{BehaviorMode, RouteBindingsRepository};
    use nrr_domain::LeakProtection;

    const PRIMARY: &str = "prefer-primary";
    const SECONDARY: &str = "prefer-secondary-when-available";
    const STRICT: &str = "strict-secondary-fail-closed";
    // Coverage codes as stored: 0 per address, 1 every unresolved
    // destination, 2 zone widening (never implemented).
    let cases: [(OldPolicy, LeakProtection, BehaviorMode); 11] = [
        (
            OldPolicy {
                sid: "S-off-not-enabled",
                mode: Some(PRIMARY),
                enabled: 0,
                fail_closed: 1,
                block_all: 1,
                coverage: 1,
            },
            LeakProtection::Off,
            BehaviorMode::PreferPrimary,
        ),
        (
            OldPolicy {
                sid: "S-off-fail-open",
                mode: Some(SECONDARY),
                enabled: 1,
                fail_closed: 0,
                block_all: 1,
                coverage: 1,
            },
            LeakProtection::Off,
            BehaviorMode::PreferSecondaryWhenAvailable,
        ),
        (
            OldPolicy {
                sid: "S-everything-full-mode",
                mode: Some(SECONDARY),
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 0,
            },
            LeakProtection::Everything,
            BehaviorMode::PreferSecondaryWhenAvailable,
        ),
        (
            OldPolicy {
                sid: "S-everything-strict",
                mode: Some(STRICT),
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 0,
            },
            LeakProtection::Everything,
            BehaviorMode::PreferSecondaryWhenAvailable,
        ),
        (
            OldPolicy {
                sid: "S-strict-guard-off",
                mode: Some(STRICT),
                enabled: 0,
                fail_closed: 1,
                block_all: 0,
                coverage: 0,
            },
            // Chosen for "no leaks": the guard switch never weakens it.
            LeakProtection::Everything,
            BehaviorMode::PreferSecondaryWhenAvailable,
        ),
        (
            OldPolicy {
                sid: "S-strict-fail-open",
                mode: Some(STRICT),
                enabled: 1,
                fail_closed: 0,
                block_all: 0,
                coverage: 0,
            },
            LeakProtection::Everything,
            BehaviorMode::PreferSecondaryWhenAvailable,
        ),
        (
            OldPolicy {
                sid: "S-everything-block-all",
                mode: Some(PRIMARY),
                enabled: 1,
                fail_closed: 1,
                block_all: 1,
                coverage: 0,
            },
            LeakProtection::Everything,
            BehaviorMode::PreferPrimary,
        ),
        (
            OldPolicy {
                sid: "S-everything-unresolved",
                mode: Some(PRIMARY),
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 1,
            },
            LeakProtection::Everything,
            BehaviorMode::PreferPrimary,
        ),
        (
            OldPolicy {
                sid: "S-sites",
                mode: Some(PRIMARY),
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 0,
            },
            LeakProtection::Sites,
            BehaviorMode::PreferPrimary,
        ),
        (
            OldPolicy {
                sid: "S-sites-zone-widening",
                mode: Some(PRIMARY),
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 2,
            },
            LeakProtection::Sites,
            BehaviorMode::PreferPrimary,
        ),
        // A policy saved without a mode row reads as the main default route.
        (
            OldPolicy {
                sid: "S-sites-no-mode-row",
                mode: None,
                enabled: 1,
                fail_closed: 1,
                block_all: 0,
                coverage: 0,
            },
            LeakProtection::Sites,
            BehaviorMode::PreferPrimary,
        ),
    ];

    let dir = tempfile::tempdir().expect("temp dir");
    state_db_before_leak_protection(&dir);
    {
        let conn = open_connection(&dir.path().join("state.db")).expect("reopen");
        for (row, _, _) in &cases {
            write_old_policy(&conn, row);
        }
        // A strict mode with no policy row of its own still folds.
        conn.execute(
            "INSERT INTO behavior_mode (sid, mode, updated_at) VALUES ('S-mode-only', ?1, 1)",
            [STRICT],
        )
        .expect("mode-only row");
    }

    let current = state_runner(&dir);
    current.run_pending_migrations().expect("upgrade");
    assert!(current.verify_schema().expect("verify").is_ok());
    let conn = current.into_connection();
    let repo = RouteBindingsRepository::new(&conn);
    for (row, protection, mode) in &cases {
        let loaded = repo.load_for_sid(row.sid).expect("load migrated policy");
        assert_eq!(loaded.leak_protection, *protection, "{}", row.sid);
        assert_eq!(loaded.mode, *mode, "{}", row.sid);
        assert_eq!(
            loaded.kill_switch_protocols, 5,
            "{}: refinements survive",
            row.sid
        );
    }
    let mode_only = repo.load_for_sid("S-mode-only").expect("load");
    assert_eq!(mode_only.mode, BehaviorMode::PreferSecondaryWhenAvailable);
    assert_eq!(
        mode_only.leak_protection,
        LeakProtection::Everything,
        "never weaker than the strict mode"
    );
    // The row the migration creates carries the app's defaults, not the
    // columns' older ones.
    assert!(mode_only.include_subdomains);
    assert!(mode_only.allow_dns_over_primary);

    let columns: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('secondary_block_policy')")
        .expect("prepare")
        .query_map([], |r| r.get(0))
        .expect("query")
        .collect::<rusqlite::Result<_>>()
        .expect("columns");
    for gone in [
        "kill_switch_enabled",
        "kill_switch_fail_closed",
        "kill_switch_block_all",
        "mode_a_coverage_strategy",
        "block_ipv6_when_protected",
    ] {
        assert!(!columns.iter().any(|c| c == gone), "{gone} survived");
    }
}

/// The install-time strict mode folds the same way, keeps its guarantee as a
/// floor of everything, and the other answer of the singleton is kept.
#[test]
fn install_time_strict_mode_becomes_the_additional_default_route() {
    use crate::install_policy::{InstallPolicyRepository, SecondaryUnset};
    use crate::route_bindings::BehaviorMode;
    use nrr_domain::LeakProtection;

    let dir = tempfile::tempdir().expect("temp dir");
    state_db_before_leak_protection(&dir);
    open_connection(&dir.path().join("state.db"))
        .expect("reopen")
        .execute(
            "INSERT INTO install_policy (id, secondary_unset, default_route_mode, updated_at)
             VALUES (1, 'block', 'strict-secondary-fail-closed', 7)",
            [],
        )
        .expect("old install policy");

    let current = state_runner(&dir);
    current.run_pending_migrations().expect("upgrade");
    let conn = current.into_connection();
    let policy = InstallPolicyRepository::new(&conn).get().expect("get");
    assert_eq!(policy.secondary_unset, SecondaryUnset::Block);
    assert_eq!(
        policy.default_route_mode,
        Some(BehaviorMode::PreferSecondaryWhenAvailable)
    );
    assert_eq!(policy.default_leak_protection, LeakProtection::Everything);
}

/// Any other install-time mode sets no protection floor.
#[test]
fn install_time_other_modes_set_no_protection_floor() {
    use crate::install_policy::InstallPolicyRepository;
    use crate::route_bindings::BehaviorMode;
    use nrr_domain::LeakProtection;

    for (stored, expected) in [
        ("", None),
        ("prefer-primary", Some(BehaviorMode::PreferPrimary)),
        (
            "prefer-secondary-when-available",
            Some(BehaviorMode::PreferSecondaryWhenAvailable),
        ),
    ] {
        let dir = tempfile::tempdir().expect("temp dir");
        state_db_before_leak_protection(&dir);
        open_connection(&dir.path().join("state.db"))
            .expect("reopen")
            .execute(
                "INSERT INTO install_policy (id, default_route_mode, updated_at) VALUES (1, ?1, 7)",
                [stored],
            )
            .expect("old install policy");

        let current = state_runner(&dir);
        current.run_pending_migrations().expect("upgrade");
        let conn = current.into_connection();
        let policy = InstallPolicyRepository::new(&conn).get().expect("get");
        assert_eq!(policy.default_route_mode, expected, "{stored:?}");
        assert_eq!(
            policy.default_leak_protection,
            LeakProtection::Off,
            "{stored:?}"
        );
    }
}

/// The strict mode is gone from the schema, not only from the code.
#[test]
fn the_strict_mode_and_unknown_protections_are_refused_by_the_schema() {
    let dir = tempfile::tempdir().expect("temp dir");
    let runner = state_runner(&dir);
    runner.run_pending_migrations().expect("migrate");
    let conn = runner.into_connection();
    let strict = "strict-secondary-fail-closed";
    assert!(conn
        .execute(
            "INSERT INTO behavior_mode (sid, mode, updated_at) VALUES ('S', ?1, 1)",
            [strict],
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO install_policy (id, default_route_mode, updated_at) VALUES (1, ?1, 1)",
            [strict],
        )
        .is_err());
    assert!(conn
        .execute(
            "INSERT INTO secondary_block_policy (sid, updated_at, leak_protection) \
             VALUES ('S', 1, 'on')",
            [],
        )
        .is_err());
}

/// A user who never chose the automatic external-address check does not get it
/// from an upgrade, whatever else their policy row holds.
#[test]
fn the_external_address_check_starts_off_for_existing_users() {
    use crate::route_bindings::RouteBindingsRepository;

    let dir = tempfile::tempdir().expect("temp dir");
    let before = STATE_MIGRATIONS
        .iter()
        .position(|m| m.name == "add_external_address_auto_check")
        .expect("the external-address migration is catalogued");
    {
        let older = state_runner_stopped_at(&dir, before);
        older
            .run_pending_migrations()
            .expect("migrate to the previous version");
        let conn = older.into_connection();
        conn.execute(
            "INSERT INTO secondary_block_policy (sid, updated_at, leak_protection, primary_probe_auto) \
             VALUES ('S-1-5-21-existing', 1, 'everything', 1)",
            [],
        )
        .expect("a row an earlier build wrote");
    }

    let current = state_runner(&dir);
    current.run_pending_migrations().expect("upgrade");
    assert!(current.verify_schema().expect("verify").is_ok());
    let conn = current.into_connection();
    let record = RouteBindingsRepository::new(&conn)
        .load_for_sid("S-1-5-21-existing")
        .expect("load");
    assert!(!record.external_address_auto_check);
    assert!(
        record.primary_probe_auto,
        "the rest of the row is carried over"
    );
    assert!(conn
        .execute(
            "UPDATE secondary_block_policy SET external_address_auto_check = 2",
            [],
        )
        .is_err());
}
