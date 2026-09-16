use super::*;
use crate::migration::{open_connection, SqliteMigrationRunner};
use crate::repository::MigrationRunner;
use tempfile::TempDir;

fn fresh_db() -> (TempDir, Connection) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("nrr_service_state.db");
    let conn = open_connection(&path).expect("open conn");
    let runner = SqliteMigrationRunner::for_state_db(conn);
    runner.run_pending_migrations().expect("run migrations");
    runner.verify_schema().expect("verify schema");
    (dir, runner.into_connection())
}

#[test]
fn link_provider_apps_roundtrip_replace_clear_and_dedupe() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let sid = "S-1-5-21-A";

    // Empty until configured; independent of route bindings.
    assert!(repo
        .load_link_provider_apps(sid, "secondary")
        .expect("load empty")
        .is_empty());

    let apps = vec![
        LinkProviderAppRecord {
            exe_path: "C:\\VPN\\client.exe".into(),
            display_name: "client.exe".into(),
        },
        // Case-insensitive duplicate — collapsed, first display name wins.
        LinkProviderAppRecord {
            exe_path: "C:\\vpn\\CLIENT.EXE".into(),
            display_name: "dup".into(),
        },
        LinkProviderAppRecord {
            exe_path: "C:\\VPN\\helper.exe".into(),
            display_name: "helper".into(),
        },
    ];
    repo.set_link_provider_apps(sid, "secondary", &apps, 1)
        .expect("set");
    let loaded = repo
        .load_link_provider_apps(sid, "secondary")
        .expect("load");
    assert_eq!(loaded.len(), 2, "case-insensitive dup collapsed");
    assert_eq!(loaded[0].exe_path, "C:\\VPN\\client.exe");
    assert_eq!(loaded[0].display_name, "client.exe");
    assert_eq!(loaded[1].exe_path, "C:\\VPN\\helper.exe");

    // Other role and other SID are isolated.
    assert!(repo
        .load_link_provider_apps(sid, "primary")
        .expect("other role")
        .is_empty());
    assert!(repo
        .load_link_provider_apps("S-1-5-21-B", "secondary")
        .expect("other sid")
        .is_empty());

    // Full replacement, then clear.
    repo.set_link_provider_apps(
        sid,
        "secondary",
        &[LinkProviderAppRecord {
            exe_path: "C:\\Other\\wg.exe".into(),
            display_name: "wg".into(),
        }],
        2,
    )
    .expect("replace");
    let replaced = repo
        .load_link_provider_apps(sid, "secondary")
        .expect("load replaced");
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].exe_path, "C:\\Other\\wg.exe");
    repo.set_link_provider_apps(sid, "secondary", &[], 3)
        .expect("clear");
    assert!(repo
        .load_link_provider_apps(sid, "secondary")
        .expect("load cleared")
        .is_empty());

    // Update of route bindings must NOT touch the provider set.
    repo.set_link_provider_apps(
        sid,
        "secondary",
        &[LinkProviderAppRecord {
            exe_path: "C:\\VPN\\client.exe".into(),
            display_name: "client.exe".into(),
        }],
        4,
    )
    .expect("set again");
    repo.update_for_sid(sid, &sample_record(BindingSource::UserAssigned), 5)
        .expect("update bindings");
    assert_eq!(
        repo.load_link_provider_apps(sid, "secondary")
            .expect("survives rebind")
            .len(),
        1,
        "re-binding adapters must not wipe configured provider apps"
    );

    // Validation: empty sid / empty exe_path rejected.
    assert!(repo
        .set_link_provider_apps("", "secondary", &[], 6)
        .is_err());
    assert!(repo
        .set_link_provider_apps(
            sid,
            "secondary",
            &[LinkProviderAppRecord {
                exe_path: "  ".into(),
                display_name: "x".into(),
            }],
            7,
        )
        .is_err());
}

fn sample_record(source: BindingSource) -> RoutePolicyRecord {
    RoutePolicyRecord {
        primary: Some(RouteBindingRecord {
            stable_id: "Wi-Fi".into(),
            display_name: "Wi-Fi".into(),
            user_confirmed: true,
            // update_for_sid seeds a first-time binding's known set to its
            // own id, so the round-trip expectation matches.
            known_stable_ids: vec!["Wi-Fi".into()],
        }),
        secondary: Some(RouteBindingRecord {
            stable_id: "TAP".into(),
            display_name: "OpenVPN TAP".into(),
            user_confirmed: false,
            known_stable_ids: vec!["TAP".into()],
        }),
        mode: BehaviorMode::StrictSecondaryFailClosed,
        block_secondary_when_unavailable: true,
        // Non-default (default is `true`) so the round-trip test proves
        // the v15 column actually persists rather than reading the default.
        kill_switch_fail_closed: false,
        // Non-default (default is all = 127) so the round-trip test proves
        // the v16 column persists rather than reading the default.
        kill_switch_protocols: 0x05, // TCP + ICMP only
        // Non-default (default is false) — proves the v23 column round-trips.
        kill_switch_block_all: true,
        // Non-default (default is `false`) — proves the v26 master-toggle
        // column persists rather than reading the default.
        kill_switch_enabled: true,
        // Non-default — proves the v27 DNS-over-primary column round-trips.
        allow_dns_over_primary: true,
        // Non-default (default is `true`) so the round-trip test proves
        // the v20 column persists rather than reading the default.
        include_subdomains: false,
        shared_ip_policy: SharedIpPolicy::MajorityOfRules,
        // Non-default (default is fail-closed-unknown) — proves the v28
        // Mode-A coverage column round-trips rather than reading the
        // default.
        mode_a_coverage_strategy: ModeACoverageStrategy::ZoneWidening,
        // Non-default (default is `true`) — proves the v28 hosts-bypass column
        // persists rather than reading the default.
        resolve_hosts_bypass: false,
        // Non-default (defaults are false / leak-protection-only) — proves the
        // v31 DoH-lockdown columns round-trip rather than reading the default.
        doh_lockdown_enabled: true,
        doh_lockdown_scope: DohLockdownScope::Always,
        // Non-default (default is `false`) — proves the v32 auto-seed column
        // round-trips rather than reading the default.
        browser_history_auto_seed: true,
        // Non-default (default is `false` = smart) — proves the v33
        // strict-shared-IPs column round-trips rather than reading the
        // default.
        kill_switch_strict_shared_ips: true,
        // Non-default (default is `suggest`) — proves the v42 auto-rules
        // column round-trips rather than reading the default.
        auto_rules_mode: AutoRulesMode::Auto,
        // Non-default (default is `false`) — proves the v46 eager
        // delivery-name column round-trips rather than reading the default.
        auto_rules_eager_delivery_names: true,
        primary_probe_auto: true,
        primary_probe_timeout_ms: 900,
        primary_probe_max_targets: 4,
        primary_probe_repeat_secs: 120,
        local_networks_auto_accept: false,
        zone_priority_over_ip: false,
        binding_source: source,
    }
}

#[test]
fn slugs_roundtrip_for_all_known_variants() {
    for src in [
        BindingSource::UserAssigned,
        BindingSource::MigratedFromPreferences,
        BindingSource::Recovery,
    ] {
        assert_eq!(BindingSource::from_slug(src.slug()), Some(src));
    }
    for m in [
        BehaviorMode::PreferPrimary,
        BehaviorMode::PreferSecondaryWhenAvailable,
        BehaviorMode::StrictSecondaryFailClosed,
    ] {
        assert_eq!(BehaviorMode::from_slug(m.slug()), Some(m));
    }
    assert_eq!(BindingSource::from_slug("garbage"), None);
    assert_eq!(BehaviorMode::from_slug("garbage"), None);
}

#[test]
fn empty_sid_load_returns_default_record() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let r = repo.load_for_sid("S-1-5-21-0").expect("load");
    assert!(r.primary.is_none());
    assert!(r.secondary.is_none());
    assert_eq!(r.mode, BehaviorMode::PreferPrimary);
    assert!(
        r.block_secondary_when_unavailable,
        "leak-guard must default ON (block 16.HW-0702) so an un-configured \
             SID never leaks secondary-bound traffic to the primary link"
    );
    assert!(
        r.kill_switch_fail_closed,
        "kill-switch posture must default to fail-closed"
    );
    assert!(
        r.allow_dns_over_primary,
        "DNS-over-primary must default ON (block 16.HW-0716 P1b) — a \
             DNS-cut block-all is a total blackout and the FQDN cache never fills"
    );
    assert_eq!(r.binding_source, BindingSource::UserAssigned);
}

#[test]
fn update_then_load_round_trips_full_record() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let rec = sample_record(BindingSource::UserAssigned);
    repo.update_for_sid("S-1-5-21-A", &rec, 1_700_000_000)
        .expect("update");
    let loaded = repo.load_for_sid("S-1-5-21-A").expect("load");
    assert_eq!(loaded, rec);
}

/// A setting the user turned on has to survive the service restart that
/// closes and reopens the database, not merely the connection that wrote it.
#[test]
fn eager_delivery_names_survives_reopen_and_defaults_off() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("nrr_service_state.db");
    let sid = "S-1-5-21-A";
    {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let repo = RouteBindingsRepository::new(&conn);
        assert!(
            !repo
                .load_for_sid(sid)
                .expect("load")
                .auto_rules_eager_delivery_names,
            "an un-configured principal must not get eager suggestions"
        );
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.auto_rules_eager_delivery_names = true;
        repo.update_for_sid(sid, &rec, 1_700_000_000)
            .expect("update");
    }

    let conn = open_connection(&path).expect("reopen");
    let repo = RouteBindingsRepository::new(&conn);
    assert!(
        repo.load_for_sid(sid)
            .expect("load after reopen")
            .auto_rules_eager_delivery_names
    );
}

/// "Stop asking me about local networks I have not seen before." Off unless
/// the user says otherwise: opening a segment unasked is their call.
#[test]
fn local_networks_auto_accept_survives_reopen_and_defaults_off() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("nrr_service_state.db");
    let sid = "S-1-5-21-A";
    {
        let conn = open_connection(&path).expect("open");
        let runner = SqliteMigrationRunner::for_state_db(conn);
        runner.run_pending_migrations().expect("migrate");
        let conn = runner.into_connection();
        let repo = RouteBindingsRepository::new(&conn);
        assert!(
            !repo
                .load_for_sid(sid)
                .expect("load")
                .local_networks_auto_accept,
            "an un-configured principal is still asked",
        );
        let mut rec = sample_record(BindingSource::UserAssigned);
        rec.local_networks_auto_accept = true;
        repo.update_for_sid(sid, &rec, 1_700_000_000)
            .expect("update");
    }

    let conn = open_connection(&path).expect("reopen");
    let repo = RouteBindingsRepository::new(&conn);
    assert!(
        repo.load_for_sid(sid)
            .expect("load after reopen")
            .local_networks_auto_accept,
    );
}

#[test]
fn update_isolates_state_per_sid() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let a = sample_record(BindingSource::UserAssigned);
    let mut b = sample_record(BindingSource::MigratedFromPreferences);
    b.primary = Some(RouteBindingRecord {
        stable_id: "Ethernet".into(),
        display_name: "Wired".into(),
        user_confirmed: true,
        known_stable_ids: vec!["Ethernet".into()],
    });
    b.secondary = None;
    b.mode = BehaviorMode::PreferPrimary;
    b.block_secondary_when_unavailable = false;
    repo.update_for_sid("A", &a, 1).expect("a");
    repo.update_for_sid("B", &b, 2).expect("b");
    assert_eq!(repo.load_for_sid("A").unwrap(), a);
    assert_eq!(repo.load_for_sid("B").unwrap(), b);
}

#[test]
fn update_rejects_primary_equals_secondary() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = Some(RouteBindingRecord {
        stable_id: rec.primary.as_ref().unwrap().stable_id.clone(),
        display_name: "dup".into(),
        user_confirmed: true,
        known_stable_ids: vec![],
    });
    let err = repo.update_for_sid("S", &rec, 1).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("same adapter"), "msg = {msg}");
}

#[test]
fn update_rejects_strict_mode_without_secondary() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = None;
    rec.mode = BehaviorMode::StrictSecondaryFailClosed;
    let err = repo.update_for_sid("S", &rec, 1).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("strict"), "msg = {msg}");
}

#[test]
fn update_rejects_empty_sid() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let rec = sample_record(BindingSource::UserAssigned);
    let err = repo.update_for_sid("", &rec, 1).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("SID is empty"), "msg = {msg}");
}

#[test]
fn second_update_replaces_secondary_when_omitted() {
    // Initial: primary + secondary. Second update: only primary, no
    // secondary. The repository must DELETE the old secondary row,
    // not leave it dangling.
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    repo.update_for_sid("S", &rec, 1).unwrap();
    rec.secondary = None;
    rec.mode = BehaviorMode::PreferPrimary;
    repo.update_for_sid("S", &rec, 2).unwrap();
    let loaded = repo.load_for_sid("S").unwrap();
    assert!(loaded.secondary.is_none());
    assert_eq!(loaded.primary.unwrap().stable_id, "Wi-Fi");
}

// ── known_stable_ids ────────────────────────────────────────────────────

fn secondary_binding(stable: &str, name: &str) -> RouteBindingRecord {
    RouteBindingRecord {
        stable_id: stable.into(),
        display_name: name.into(),
        user_confirmed: true,
        known_stable_ids: vec![stable.into()],
    }
}

#[test]
fn heal_binding_identity_unions_old_and_new_ids() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = Some(secondary_binding(
        "win-adapter:{guid-a}",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    repo.update_for_sid("S", &rec, 1).unwrap();

    // VPN reinstalled: new GUID + a version-bumped friendly name.
    repo.heal_binding_identity(
        "S",
        "secondary",
        "win-adapter:{guid-b}",
        "SwiftVPN 3.0 OpenVPN Adapter",
        2,
    )
    .unwrap();

    let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
    assert_eq!(s.stable_id, "win-adapter:{guid-b}");
    assert_eq!(s.display_name, "SwiftVPN 3.0 OpenVPN Adapter");
    assert!(s
        .known_stable_ids
        .contains(&"win-adapter:{guid-a}".to_string()));
    assert!(s
        .known_stable_ids
        .contains(&"win-adapter:{guid-b}".to_string()));
}

#[test]
fn remember_stable_id_adds_once_and_keeps_the_binding_pointing_where_it_did() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = Some(secondary_binding("win-adapter:{guid-a}", "Wi-Fi"));
    repo.update_for_sid("S", &rec, 1).unwrap();

    assert!(repo
        .remember_stable_id("S", "secondary", "win-mac:00-11-22-33-44-AA", 2)
        .unwrap());
    assert!(
        !repo
            .remember_stable_id("S", "secondary", "win-mac:00-11-22-33-44-aa", 3)
            .unwrap(),
        "a known id, however it is spelled, must not grow the set again"
    );

    let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
    assert_eq!(s.stable_id, "win-adapter:{guid-a}");
    assert!(s
        .known_stable_ids
        .contains(&"win-mac:00-11-22-33-44-AA".to_string()));
}

#[test]
fn remember_stable_id_is_a_noop_without_a_binding() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    assert!(!repo
        .remember_stable_id("S", "secondary", "win-mac:00-11-22-33-44-55", 1)
        .unwrap());
}

#[test]
fn update_preserves_known_ids_across_unrelated_change() {
    // guid-a bound, healed to guid-b (known = {a, b}). A later user save that
    // keeps the same (healed) secondary — e.g. toggling an unrelated policy —
    // must NOT drop the accumulated ids.
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = Some(secondary_binding("win-adapter:{guid-a}", "VPN"));
    repo.update_for_sid("S", &rec, 1).unwrap();
    repo.heal_binding_identity("S", "secondary", "win-adapter:{guid-b}", "VPN", 2)
        .unwrap();

    // GUI reads back guid-b and re-saves the same binding on a settings change.
    let reloaded = repo.load_for_sid("S").unwrap();
    repo.update_for_sid("S", &reloaded, 3).unwrap();

    let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
    assert!(
        s.known_stable_ids
            .contains(&"win-adapter:{guid-a}".to_string()),
        "known ids must survive an unrelated re-save: {:?}",
        s.known_stable_ids
    );
    assert!(s
        .known_stable_ids
        .contains(&"win-adapter:{guid-b}".to_string()));
}

#[test]
fn update_resets_known_ids_on_genuine_rebind() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let mut rec = sample_record(BindingSource::UserAssigned);
    rec.secondary = Some(secondary_binding("win-adapter:{guid-a}", "VPN A"));
    repo.update_for_sid("S", &rec, 1).unwrap();
    repo.heal_binding_identity("S", "secondary", "win-adapter:{guid-b}", "VPN A", 2)
        .unwrap();

    // User binds a genuinely different adapter.
    let mut rebind = sample_record(BindingSource::UserAssigned);
    rebind.secondary = Some(RouteBindingRecord {
        stable_id: "win-adapter:{guid-c}".into(),
        display_name: "Some Other VPN".into(),
        user_confirmed: true,
        known_stable_ids: vec![],
    });
    repo.update_for_sid("S", &rebind, 3).unwrap();

    let s = repo.load_for_sid("S").unwrap().secondary.unwrap();
    assert_eq!(
        s.known_stable_ids,
        vec!["win-adapter:{guid-c}".to_string()],
        "a genuine re-bind must reset the known-id set"
    );
}

#[test]
fn heal_binding_identity_is_noop_when_absent() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    repo.heal_binding_identity("S", "secondary", "x", "y", 1)
        .unwrap();
    assert!(repo.load_for_sid("S").unwrap().secondary.is_none());
}

#[test]
fn migration_status_returns_none_before_mark() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    let r = repo.migration_status("S", "legacy_preferences_v1").unwrap();
    assert!(r.is_none());
}

#[test]
fn mark_migration_then_status_returns_some() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    repo.mark_migration_complete("S", "legacy_preferences_v1", Some(r#"{"n":3}"#), 99)
        .unwrap();
    let r = repo
        .migration_status("S", "legacy_preferences_v1")
        .unwrap()
        .unwrap();
    assert_eq!(r.completed_at, 99);
    assert_eq!(r.detail_json.as_deref(), Some(r#"{"n":3}"#));
}

#[test]
fn mark_migration_is_idempotent_keeps_first_timestamp() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    repo.mark_migration_complete("S", "id", None, 100).unwrap();
    // Second call with later timestamp must not overwrite.
    repo.mark_migration_complete("S", "id", Some("later"), 200)
        .unwrap();
    let r = repo.migration_status("S", "id").unwrap().unwrap();
    assert_eq!(r.completed_at, 100);
    assert_eq!(r.detail_json, None);
}

#[test]
fn mark_migration_per_sid_is_independent() {
    let (_dir, conn) = fresh_db();
    let repo = RouteBindingsRepository::new(&conn);
    repo.mark_migration_complete("A", "id", None, 1).unwrap();
    let a = repo.migration_status("A", "id").unwrap();
    let b = repo.migration_status("B", "id").unwrap();
    assert!(a.is_some());
    assert!(b.is_none());
}

// ── The third copy of the policy defaults ────────────────────────────────

/// Every wire key whose default this row owns, paired with the row's value
/// rendered the way the wire renders it.
///
/// Two keys are deliberately absent. `mode` is not a block-policy field at
/// all, and `block-secondary-when-unavailable` has no wire default (the
/// request always carries it), so the GUI's entry for it is a fallback for
/// an empty snapshot rather than a mirror of this row.
fn row_defaults_as_wire() -> Vec<(&'static str, serde_json::Value)> {
    use serde_json::json;
    let row = BlockPolicyRow::default();
    vec![
        (
            "kill-switch-fail-closed",
            json!(row.kill_switch_fail_closed),
        ),
        ("kill-switch-protocols", json!(row.kill_switch_protocols)),
        ("kill-switch-block-all", json!(row.kill_switch_block_all)),
        ("kill-switch-enabled", json!(row.kill_switch_enabled)),
        ("allow-dns-over-primary", json!(row.allow_dns_over_primary)),
        ("include-subdomains", json!(row.include_subdomains)),
        ("shared-ip-policy", json!(row.shared_ip_policy.as_slug())),
        (
            "mode-a-coverage-strategy",
            json!(row.mode_a_coverage_strategy.as_slug()),
        ),
        ("resolve-hosts-bypass", json!(row.resolve_hosts_bypass)),
        ("doh-lockdown-enabled", json!(row.doh_lockdown_enabled)),
        (
            "doh-lockdown-scope",
            json!(row.doh_lockdown_scope.as_slug()),
        ),
        (
            "browser-history-auto-seed",
            json!(row.browser_history_auto_seed),
        ),
        (
            "kill-switch-strict-shared-ips",
            json!(row.kill_switch_strict_shared_ips),
        ),
        ("auto-rules-mode", json!(row.auto_rules_mode.as_slug())),
        (
            "auto-rules-eager-delivery-names",
            json!(row.auto_rules_eager_delivery_names),
        ),
        ("primary-probe-auto", json!(row.primary_probe_auto)),
        (
            "primary-probe-timeout-ms",
            json!(row.primary_probe_timeout_ms),
        ),
        (
            "primary-probe-max-targets",
            json!(row.primary_probe_max_targets),
        ),
        (
            "primary-probe-repeat-secs",
            json!(row.primary_probe_repeat_secs),
        ),
        (
            "local-networks-auto-accept",
            json!(row.local_networks_auto_accept),
        ),
        ("zone-priority-over-ip", json!(row.zone_priority_over_ip)),
    ]
}

/// The GUI's declaration of the same defaults, parsed from its single
/// source. Same literal the wire-contract test in `nrr-shared` reads.
fn qml_field_defaults() -> serde_json::Map<String, serde_json::Value> {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../apps/desktop/qml/lib/pure.js");
    let source =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let decl = "var ROUTE_POLICY_FIELD_DEFAULTS = ";
    let start = source
        .find(decl)
        .expect("ROUTE_POLICY_FIELD_DEFAULTS declaration missing from lib/pure.js")
        + decl.len();
    let body = &source[start..];
    let mut depth = 0usize;
    let mut end = None;
    for (idx, ch) in body.char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                end = Some(idx + ch.len_utf8());
                break;
            }
        }
    }
    let end = end.expect("unbalanced ROUTE_POLICY_FIELD_DEFAULTS literal");
    match serde_json::from_str(&body[..end]) {
        Ok(serde_json::Value::Object(map)) => map,
        other => panic!("ROUTE_POLICY_FIELD_DEFAULTS must parse as an object: {other:?}"),
    }
}

/// A user with no saved row gets this row; the panel that renders their
/// policy gets the GUI table. The two are written out separately, in
/// different languages, so nothing but a test can keep them equal — and
/// until this one existed, changing a default here passed every gate while
/// the interface went on showing the other value.
#[test]
fn block_policy_defaults_match_the_gui_declaration() {
    let declared = qml_field_defaults();
    let mut diverged = Vec::new();
    for (key, ours) in row_defaults_as_wire() {
        let theirs = declared
            .get(key)
            .unwrap_or_else(|| panic!("ROUTE_POLICY_FIELD_DEFAULTS has no `{key}`"));
        if theirs != &ours {
            diverged.push(format!("{key}: storage={ours}, pure.js={theirs}"));
        }
    }
    assert!(
        diverged.is_empty(),
        "storage defaults and apps/desktop/qml/lib/pure.js disagree: {}",
        diverged.join("; ")
    );
}
