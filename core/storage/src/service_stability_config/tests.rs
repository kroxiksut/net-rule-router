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
fn default_is_recoverable_with_canonical_constants() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    let r = repo.get_or_default().expect("get");
    match r.ipc_accept_policy {
        IpcAcceptPolicyRecord::Recoverable {
            max_restarts,
            backoff_base_ms,
            backoff_cap_ms,
        } => {
            assert_eq!(max_restarts, DEFAULT_IPC_MAX_RESTARTS);
            assert_eq!(backoff_base_ms, DEFAULT_IPC_BACKOFF_BASE_MS);
            assert_eq!(backoff_cap_ms, DEFAULT_IPC_BACKOFF_CAP_MS);
        }
        other => panic!("expected Recoverable default, got {other:?}"),
    }
    assert!(r.set_by_sid.is_none());
    assert_eq!(r.updated_at, 0);
}

#[test]
fn verbose_logging_defaults_to_false_for_implicit_record() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    let r = repo.get_or_default().expect("get");
    assert!(
        !r.verbose_logging,
        "implicit default must have verbose=false"
    );
}

#[test]
fn verbose_logging_roundtrips_through_set_and_get() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        true,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-X"),
        42,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(r.verbose_logging, "verbose=true must be persisted");

    // Critical-with-verbose-true is a valid combination — the
    // schema CHECK only constrains the policy parameter columns.
    assert_eq!(r.ipc_accept_policy, IpcAcceptPolicyRecord::Critical);
}

/// Direct coverage for the standalone boot-time probe.
/// `main.rs`/`scm.rs` call `probe_verbose_logging` (not the repository
/// directly) on a short-lived connection before installing the tracing
/// subscriber, so this is the exact function that must reflect a saved
/// GUI toggle at service startup.
#[test]
fn probe_verbose_logging_reflects_persisted_value() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    assert!(
        !probe_verbose_logging(&conn),
        "implicit default must probe false"
    );

    let repo = ServiceStabilityConfigRepository::new(&conn);
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        true,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-PROBE"),
        1,
    )
    .expect("set");
    assert!(
        probe_verbose_logging(&conn),
        "probe must observe a persisted verbose=true row"
    );
}

#[test]
fn fake_ip_enabled_defaults_false_and_roundtrips() {
    // Block D (S4.7) — machine-wide fake-IP toggle: off for the implicit
    // default record and for a pre-v34 row; an explicit `true` persists.
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    assert!(
        !repo.get_or_default().expect("get").fake_ip_enabled,
        "implicit default must be off (opt-in feature)"
    );
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Resolver,
        0,
        true,
        false,
        true,
        false,
        true,
        true,
        Some("S-FIP"),
        21,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(r.fake_ip_enabled, "fake_ip_enabled=true must persist");
    // Unrelated flags untouched.
    assert!(!r.verbose_logging && !r.conn_trace_ndjson);
}

#[test]
fn fake_ip_udp_relay_defaults_false_and_roundtrips() {
    // Fake-IP UDP relay: off for the implicit default record and for a
    // pre-v39 row; an explicit `true` persists independently of
    // `fake_ip_enabled`.
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    assert!(
        !repo.get_or_default().expect("get").fake_ip_udp_relay,
        "implicit default must be off (opt-in feature)"
    );
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Resolver,
        0,
        true,
        false,
        true,
        true,
        true,
        true,
        Some("S-UDPRELAY"),
        22,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(r.fake_ip_udp_relay, "fake_ip_udp_relay=true must persist");
    assert!(
        r.fake_ip_enabled,
        "unrelated fake_ip_enabled write untouched"
    );
}

#[test]
fn fake_ip_instant_rst_defaults_true_and_roundtrips() {
    // Fake-IP instant reset: ON for the implicit default
    // record and for a pre-v40 row — today's instant-reset dial behaviour
    // is preserved until the user opts into the hold-and-retry path. An
    // explicit `false` persists independently of `fake_ip_udp_relay`.
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    assert!(
        repo.get_or_default().expect("get").fake_ip_instant_rst,
        "implicit default must be on (today's instant-reset behaviour)"
    );
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Resolver,
        0,
        true,
        false,
        true,
        true,
        false,
        true,
        Some("S-INSTANTRST"),
        23,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(
        !r.fake_ip_instant_rst,
        "fake_ip_instant_rst=false must persist"
    );
    assert!(
        r.fake_ip_udp_relay,
        "unrelated fake_ip_udp_relay write untouched"
    );
}

/// Helper mirroring the production `set` call with everything at its
/// default except the administrative rules lock.
fn set_rules_lock(repo: &ServiceStabilityConfigRepository<'_>, allow: bool, now_ms: i64) {
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Resolver,
        0,
        false,
        false,
        true,
        false,
        true,
        allow,
        Some("S-ADMIN"),
        now_ms,
    )
    .expect("set");
}

#[test]
fn allow_user_rule_edits_defaults_to_allowed() {
    // The implicit default record and a freshly migrated row must both
    // leave rule authoring open: a machine nobody configured must never
    // come up with its users silently unable to edit anything.
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    assert!(
        repo.get_or_default().expect("get").allow_user_rule_edits,
        "implicit default must allow user rule edits"
    );
    // An explicit write of every OTHER field must not disturb it either.
    set_rules_lock(&repo, true, 1);
    assert!(repo.get_or_default().expect("get").allow_user_rule_edits);
}

#[test]
fn allow_user_rule_edits_roundtrips_both_directions() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    set_rules_lock(&repo, false, 2);
    let locked = repo.get_or_default().expect("get");
    assert!(!locked.allow_user_rule_edits, "lock must persist");
    // Unrelated fields keep the values the same write carried.
    assert!(locked.rule_scope_service_driven);
    assert_eq!(locked.enforcement_mode, EnforcementMode::Resolver);

    set_rules_lock(&repo, true, 3);
    assert!(
        repo.get_or_default().expect("get").allow_user_rule_edits,
        "an administrator must be able to lift the lock again"
    );
}

#[test]
fn allow_user_rule_edits_survives_reopen() {
    // The whole value of the lock is that it outlives the session — a
    // restricted user restarting the service (or the box) must still find
    // rule authoring frozen.
    let dir = tempfile::tempdir().expect("temp dir");
    {
        let conn = open_state_db(&dir);
        set_rules_lock(&ServiceStabilityConfigRepository::new(&conn), false, 4);
    }
    let conn = open_state_db(&dir);
    assert!(
        !ServiceStabilityConfigRepository::new(&conn)
            .get_or_default()
            .expect("get")
            .allow_user_rule_edits,
        "the lock must survive a service restart"
    );
}

#[test]
fn schema_rejects_invalid_allow_user_rule_edits() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // The CHECK constrains the column to {0, 1}: a hand-edited row cannot
    // smuggle in a truthy-but-unknown value.
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at, allow_user_rule_edits)
             VALUES (1, 'critical', NULL, NULL, NULL, NULL, 1, 2)",
            [],
        );
    assert!(res.is_err(), "allow_user_rule_edits=2 must be rejected");
}

#[test]
fn conn_trace_flags_default_and_roundtrip_independently() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default: the on-disk sink is off, the GUI view is on.
    let d = repo.get_or_default().expect("get");
    assert!(!d.conn_trace_ndjson, "the disk sink stays opt-in");
    assert!(d.conn_trace_gui, "an unwritten DB still shows the panel");

    // GUI on, NDJSON off — independent toggles.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        true,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-Z"),
        7,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(!r.conn_trace_ndjson, "ndjson must stay off");
    assert!(r.conn_trace_gui, "gui must persist on");
    // Unrelated flags untouched.
    assert!(!r.verbose_logging);
}

#[test]
fn rule_scope_defaults_to_service_driven_and_roundtrips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default: service-driven (true).
    let d = repo.get_or_default().expect("get");
    assert!(
        d.rule_scope_service_driven,
        "implicit default must be service-driven"
    );

    // Flip to app-driven (false); other flags untouched.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        false,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-RS"),
        9,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert!(!r.rule_scope_service_driven, "app-driven must persist");
    assert!(!r.verbose_logging && !r.conn_trace_ndjson && !r.conn_trace_gui);
}

#[test]
fn routing_stop_policy_defaults_to_persist_and_roundtrips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default (no row): teardown ("disable/stop = back to
    // normal"; every route removed, all traffic returns to the primary channel).
    let d = repo.get_or_default().expect("get");
    assert_eq!(d.routing_stop_policy, RoutingStopPolicy::Teardown);

    // Explicit persist roundtrips; unrelated flags untouched.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-STOP"),
        11,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert_eq!(r.routing_stop_policy, RoutingStopPolicy::Persist);
    assert!(r.rule_scope_service_driven);

    // Explicit teardown (full restore-pristine) roundtrips back.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-STOP"),
        12,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default().expect("get").routing_stop_policy,
        RoutingStopPolicy::Teardown
    );
}

#[test]
fn cache_refresh_interval_defaults_and_roundtrips() {
    use nrr_domain::decision_lookup::CACHE_REFRESH_DEFAULT_SECS;
    let dir = tempfile::tempdir().expect("tmp");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default (no row) is the 5-minute recommended value.
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .cache_refresh_interval_secs,
        CACHE_REFRESH_DEFAULT_SECS
    );

    // A valid in-range value round-trips unchanged; a below-min value is
    // clamped up by the write path before it reaches the schema CHECK.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        5, // below CACHE_REFRESH_MIN_SECS → clamped to 60 on write
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-CR"),
        5,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .cache_refresh_interval_secs,
        60,
        "below-min interval is clamped up on write, never rejected by the CHECK"
    );
}

#[test]
fn enforcement_mode_defaults_to_resolver_and_roundtrips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default (no row) is Resolver. This is the value a wiped or
    // never-written state DB answers with, and it must match
    // `EnforcementMode::default()`: when it did not, a fresh service came
    // up in reactive mode and the GUI adopted that as the user's setting.
    assert_eq!(
        repo.get_or_default().expect("get").enforcement_mode,
        EnforcementMode::Resolver
    );

    // An explicit write of the default value must persist as a written row
    // (not silently collapse back to "never written"). Unrelated flags
    // untouched.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Resolver,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-EM"),
        77,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert_eq!(
        r.enforcement_mode,
        EnforcementMode::Resolver,
        "Resolver must be persisted"
    );
    assert!(r.rule_scope_service_driven);
    assert_eq!(r.routing_stop_policy, RoutingStopPolicy::Persist);

    // The off-default value round-trips too — this is the direction that
    // proves persistence rather than agreement with the default.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-EM"),
        78,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default().expect("get").enforcement_mode,
        EnforcementMode::Reactive
    );
}

#[test]
fn secondary_liveness_window_defaults_disabled_and_roundtrips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);

    // Implicit default (no row) is 0 = DISABLED (safe default — the liveness
    // probe never fail-closes).
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .secondary_liveness_window_secs,
        0
    );

    // A valid in-range value round-trips unchanged; unrelated flags untouched.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        30,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-LW"),
        13,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert_eq!(r.secondary_liveness_window_secs, 30);
    assert!(r.rule_scope_service_driven);

    // A below-min non-zero value is clamped UP to 5 on write (never rejected).
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        2,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-LW"),
        14,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .secondary_liveness_window_secs,
        5,
        "below-min non-zero window is clamped up on write"
    );

    // An above-max value is clamped DOWN to 3600 on write.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        99_999,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-LW"),
        15,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .secondary_liveness_window_secs,
        3600,
        "above-max window is clamped down on write"
    );

    // 0 (disabled) round-trips back unchanged.
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Persist,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-LW"),
        16,
    )
    .expect("set");
    assert_eq!(
        repo.get_or_default()
            .expect("get")
            .secondary_liveness_window_secs,
        0
    );
}

#[test]
fn clamp_liveness_window_secs_zero_disabled_else_bounded() {
    assert_eq!(
        clamp_liveness_window_secs(0),
        0,
        "0 is the disabled sentinel"
    );
    assert_eq!(clamp_liveness_window_secs(1), 5, "below-min clamps up to 5");
    assert_eq!(clamp_liveness_window_secs(5), 5);
    assert_eq!(clamp_liveness_window_secs(300), 300);
    assert_eq!(clamp_liveness_window_secs(3600), 3600);
    assert_eq!(
        clamp_liveness_window_secs(3601),
        3600,
        "above-max clamps down"
    );
}

#[test]
fn schema_rejects_invalid_enforcement_mode() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // The CHECK constrains the code to {0, 1}.
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at, enforcement_mode)
             VALUES (1, 'critical', NULL, NULL, NULL, NULL, 1, 2)",
            [],
        );
    assert!(res.is_err(), "enforcement_mode=2 must be rejected");
}

#[test]
fn routing_stop_policy_slug_roundtrip_and_rejects_unknown() {
    assert_eq!(RoutingStopPolicy::Teardown.as_slug(), "teardown");
    assert_eq!(RoutingStopPolicy::Persist.as_slug(), "persist");
    assert_eq!(
        RoutingStopPolicy::from_slug("persist"),
        Ok(RoutingStopPolicy::Persist)
    );
    assert!(RoutingStopPolicy::from_slug("bogus").is_err());
}

#[test]
fn routing_stop_policy_default_is_teardown() {
    assert_eq!(RoutingStopPolicy::default(), RoutingStopPolicy::Teardown);
}

#[test]
fn schema_rejects_invalid_routing_stop_policy() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // The CHECK constrains the slug to the two known values.
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at, routing_stop_policy)
             VALUES (1, 'critical', NULL, NULL, NULL, NULL, 1, 'bogus')",
            [],
        );
    assert!(res.is_err(), "invalid routing_stop_policy must be rejected");
}

#[test]
fn set_recoverable_then_get_roundtrips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    let policy = IpcAcceptPolicyWrite::Recoverable {
        max_restarts: 42,
        backoff_base_ms: 200,
        backoff_cap_ms: 7_500,
    };
    repo.set(
        &policy,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-1-5-21-test"),
        1_700_000_000,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert_eq!(r.ipc_accept_policy, policy);
    assert_eq!(r.set_by_sid.as_deref(), Some("S-1-5-21-test"));
    assert_eq!(r.updated_at, 1_700_000_000);
}

#[test]
fn set_critical_then_get_returns_critical_with_null_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-A"),
        100,
    )
    .expect("set");
    let r = repo.get_or_default().expect("get");
    assert_eq!(r.ipc_accept_policy, IpcAcceptPolicyRecord::Critical);
}

#[test]
fn set_overwrites_previous_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let repo = ServiceStabilityConfigRepository::new(&conn);
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        None,
        1,
    )
    .unwrap();
    repo.set(
        &IpcAcceptPolicyWrite::Recoverable {
            max_restarts: 50,
            backoff_base_ms: 100,
            backoff_cap_ms: 1_500,
        },
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        Some("S-B"),
        2,
    )
    .unwrap();
    let r = repo.get_or_default().unwrap();
    match r.ipc_accept_policy {
        IpcAcceptPolicyRecord::Recoverable { max_restarts, .. } => {
            assert_eq!(max_restarts, 50);
        }
        _ => panic!("expected Recoverable after second set"),
    }
    assert_eq!(r.set_by_sid.as_deref(), Some("S-B"));
    assert_eq!(r.updated_at, 2);
}

#[test]
fn schema_rejects_out_of_range_max_restarts() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // Bypass the repo to hit the SQLite CHECK directly. `0` is
    // below the lower bound.
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at)
             VALUES (1, 'recoverable', 0, 100, 5000, NULL, 1)",
            [],
        );
    assert!(res.is_err(), "max_restarts=0 must be rejected");
}

#[test]
fn schema_rejects_recoverable_with_null_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at)
             VALUES (1, 'recoverable', NULL, NULL, NULL, NULL, 1)",
            [],
        );
    assert!(
        res.is_err(),
        "recoverable kind with NULL params must be rejected"
    );
}

#[test]
fn schema_rejects_critical_with_populated_params() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at)
             VALUES (1, 'critical', 20, 100, 5000, NULL, 1)",
            [],
        );
    assert!(
        res.is_err(),
        "critical kind with populated params must be rejected"
    );
}

#[test]
fn schema_rejects_second_row() {
    let dir = tempfile::tempdir().expect("temp dir");
    let conn = open_state_db(&dir);
    // First row via repo.
    let repo = ServiceStabilityConfigRepository::new(&conn);
    repo.set(
        &IpcAcceptPolicyWrite::Critical,
        false,
        false,
        false,
        true,
        RoutingStopPolicy::Teardown,
        300,
        EnforcementMode::Reactive,
        0,
        false,
        false,
        true,
        false,
        true,
        true,
        None,
        1,
    )
    .unwrap();
    // Second row directly — must hit id=1 CHECK.
    let res = conn.execute(
            "INSERT INTO service_stability_config
                (id, ipc_accept_kind, ipc_max_restarts, ipc_backoff_base_ms, ipc_backoff_cap_ms, set_by_sid, updated_at)
             VALUES (2, 'critical', NULL, NULL, NULL, NULL, 2)",
            [],
        );
    assert!(res.is_err(), "id=2 must be rejected by CHECK(id=1)");
}

#[test]
fn validate_recoverable_params_accepts_canonical_defaults() {
    assert!(validate_recoverable_params(
        DEFAULT_IPC_MAX_RESTARTS,
        DEFAULT_IPC_BACKOFF_BASE_MS,
        DEFAULT_IPC_BACKOFF_CAP_MS
    )
    .is_ok());
}

#[test]
fn validate_recoverable_params_rejects_inverted_cap() {
    let r = validate_recoverable_params(20, 5_000, 1_000);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("backoff_cap_ms must be"));
}

#[test]
fn validate_recoverable_params_rejects_zero_restarts() {
    assert!(validate_recoverable_params(0, 100, 5_000).is_err());
}
