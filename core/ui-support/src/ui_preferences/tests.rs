/// Three copies of this default disagreed: the wire said `resolver`, the
/// field doc said `reactive`, and the QML mirror normalised a MISSING value
/// to `reactive` — a mode the code itself calls an unsupported historical
/// fallback, saved by the next `emitPrefs()`. The mirror derives it now;
/// this is the test that keeps the two from drifting apart again.
#[test]
fn the_enforcement_mode_mirror_starts_at_the_wire_default() {
    assert_eq!(
        UiPreferences::default().route_enforcement_mode,
        nrr_shared::ipc_payloads::ENFORCEMENT_MODE_DEFAULT,
    );
}

/// The writer used to accept what the reader refuses. A value with a
/// newline wrote a second `key=value` pair, and the next load read it as a
/// setting the user never touched — the wizard flag being the loudest one.
#[test]
fn a_value_with_a_newline_cannot_forge_a_second_setting() {
    let prefs = UiPreferences {
        first_run_completed: true,
        route_primary_label: "Main\nfirst_run_completed=false".to_string(),
        user_presets_dir: "/home/u/my\rrules".to_string(),
        ..UiPreferences::default()
    };

    let rendered = format_preferences(&prefs);
    let parsed = parse_preferences(&rendered);

    assert!(
        parsed.first_run_completed,
        "a label must not be able to rewrite another setting"
    );
    assert_eq!(parsed.route_primary_label, "Main first_run_completed=false");
    assert_eq!(parsed.user_presets_dir, "/home/u/my rules");
    // Every line the writer produced is still one key and one value.
    for line in rendered.lines() {
        assert!(
            !line.contains(['\r', '\n']),
            "no stray control character: {line:?}"
        );
    }
}

/// Out of range must land at the nearest bound, not at the default — and
/// the default here is the MAXIMUM, so rejecting `20` ("nearly
/// transparent") produced 100, fully opaque.
#[test]
fn an_out_of_range_opacity_clamps_instead_of_reverting_to_the_default() {
    let load = |raw: &str| {
        let text = format!(
            "tray_notice_opacity_percent={raw}
"
        );
        super::parse_preferences(&text).tray_notice_opacity_percent
    };
    assert_eq!(load("20"), super::TRAY_NOTICE_OPACITY_MIN_PERCENT);
    assert_eq!(load("400"), super::TRAY_NOTICE_OPACITY_MAX_PERCENT);
    assert_eq!(load("55"), 55);
    // Not a number at all is still a rejection: there is no nearest bound.
    assert_eq!(
        load("transparent"),
        UiPreferences::default().tray_notice_opacity_percent
    );
}

/// A read that failed after the `.bak` fallback must not hand back a
/// writable store: the file was unavailable, not empty, and the next save
/// would replace it with defaults.
#[test]
fn a_failed_read_opens_the_session_read_only() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A DIRECTORY where the preferences file belongs: readable metadata,
    // unreadable content, on every platform.
    let path = dir.path().join("prefs.conf");
    std::fs::create_dir(&path).expect("dir in place of file");
    let store = UiPreferencesStore::for_path(path);
    match super::open_for_session(store) {
        super::SessionPreferences::ReadOnly { preferences, .. } => {
            assert_eq!(preferences, UiPreferences::default());
        }
        super::SessionPreferences::Writable { .. } => {
            panic!("an unreadable file must not yield a writable store")
        }
    }
}
use super::{
    declared_schema_version, format_preferences, parse_preferences, preferred_available_language,
    without_expired_parked_intents, ForwardCompat, SystemFontFamily, UiPreferences,
    UiPreferencesStore, ADMIN_AUTO_REVOKE_MAX_MINUTES, ADMIN_AUTO_REVOKE_MIN_MINUTES,
    CURRENT_UI_PREFS_SCHEMA_VERSION, MAX_STORED_JSON_BLOB_BYTES, MAX_STORED_STRING_BYTES,
    SETTINGS_AUTOSAVE_MIN_SECS,
};
use nrr_shared::{
    AppSection, RouteBehaviorMode, RulesEnabledFilter, RulesFileChangeBehavior, RulesTypeFilter,
    RulesViewSort, ThemeMode,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn defaults_are_loaded_when_store_file_is_missing() {
    let (_dir, path) = test_path("missing.conf");
    let store = UiPreferencesStore::for_path(path);
    let loaded = store
        .load()
        .unwrap_or_else(|error| panic!("load should succeed for missing file: {error}"));
    assert_eq!(loaded, UiPreferences::default());
}

#[test]
fn parser_ignores_unknown_keys_and_preserves_known_values() {
    let parsed = parse_preferences(concat!(
        "theme_mode=high-contrast\n",
        "accessibility_high_contrast=true\n",
        "accessibility_ui_font_scale_percent=125\n",
        "accessibility_system_font=segoe-ui\n",
        "accessibility_enhanced_focus_indicator=true\n",
        "accessibility_simplified_labels=true\n",
        "tooltips_enabled=true\n",
        "first_run_completed=true\n",
        "language=en\n",
        "route_primary_label=Main\n",
        "route_secondary_label=Alternative\n",
        "last_opened_section=logs\n",
        "unknown_key=ignored\n"
    ));
    assert_eq!(parsed.theme_mode, ThemeMode::HighContrast);
    assert!(parsed.accessibility_high_contrast);
    assert_eq!(parsed.accessibility_ui_font_scale_percent, 125);
    assert_eq!(parsed.accessibility_system_font, SystemFontFamily::SegoeUi);
    assert!(parsed.accessibility_enhanced_focus_indicator);
    assert!(parsed.accessibility_simplified_labels);
    assert!(parsed.tooltips_enabled);
    assert!(parsed.first_run_completed);
    assert_eq!(parsed.language, "en");
    assert_eq!(parsed.route_primary_label, "Main");
    assert_eq!(parsed.route_secondary_label, "Alternative");
    assert_eq!(parsed.last_opened_section, AppSection::Logs);
}

#[test]
fn accepted_eula_version_defaults_to_zero_and_round_trips() {
    // Absent key → not accepted (0), so a pre-EULA preferences file
    // re-prompts the agreement on load.
    let none = parse_preferences("theme_mode=system\n");
    assert_eq!(
        none.accepted_eula_version,
        nrr_shared::eula::EULA_NOT_ACCEPTED
    );
    assert!(!nrr_shared::eula::is_accepted(none.accepted_eula_version));

    // Present key parses; a garbage value leaves the default untouched.
    let accepted = parse_preferences("accepted_eula_version=1\n");
    assert_eq!(accepted.accepted_eula_version, 1);
    let garbage = parse_preferences("accepted_eula_version=not-a-number\n");
    assert_eq!(
        garbage.accepted_eula_version,
        nrr_shared::eula::EULA_NOT_ACCEPTED
    );
}

#[test]
fn block_notice_prefs_default_when_key_absent() {
    // A file saved before these keys existed must still load cleanly,
    // with both fields falling back to their type defaults.
    let parsed = parse_preferences("theme_mode=system\n");
    assert!(parsed.notify_block_notices);
    assert!(!parsed.hide_block_notice_addresses);
}

#[test]
fn block_notice_prefs_parse_explicit_values() {
    let parsed = parse_preferences(concat!(
        "notify_block_notices=false\n",
        "hide_block_notice_addresses=true\n"
    ));
    assert!(!parsed.notify_block_notices);
    assert!(parsed.hide_block_notice_addresses);
}

#[test]
fn parser_reads_confirmed_role_fields() {
    let parsed = parse_preferences(concat!(
        "show_bluetooth_adapters=true\n",
        "selected_primary_interface_id=win-adapter:ethernet\n",
        "selected_primary_interface_name=Ethernet\n",
        "primary_role_user_confirmed=true\n",
        "selected_secondary_interface_id=win-adapter:vpn\n",
        "selected_secondary_interface_name=VPN\n",
        "secondary_role_user_confirmed=true\n"
    ));
    assert!(parsed.show_bluetooth_adapters);
    assert_eq!(parsed.selected_primary_interface_id, "win-adapter:ethernet");
    assert_eq!(parsed.selected_primary_interface_name, "Ethernet");
    assert!(parsed.primary_role_user_confirmed);
    assert_eq!(parsed.selected_secondary_interface_id, "win-adapter:vpn");
    assert_eq!(parsed.selected_secondary_interface_name, "VPN");
    assert!(parsed.secondary_role_user_confirmed);
}

/// Two writers save at once (the GUI and the tray both do). With one
/// shared `<path>.tmp` the second truncates the first one's file mid-write
/// and the first renames the other's half-written payload into place; the
/// surviving file must be one of the two, whole.
#[test]
fn concurrent_saves_never_leave_a_blended_file() {
    let (dir, path) = test_path("concurrent.conf");
    let store = UiPreferencesStore::for_path(path);
    let short = UiPreferences {
        route_primary_label: "a".repeat(8),
        ..UiPreferences::default()
    };
    let long = UiPreferences {
        route_primary_label: "b".repeat(4096),
        ..UiPreferences::default()
    };

    std::thread::scope(|scope| {
        for prefs in [&short, &long] {
            scope.spawn(|| {
                for _ in 0..20 {
                    store.save(prefs).expect("save");
                }
            });
        }
    });

    let label = store.load().expect("load").route_primary_label;
    assert!(
        label == short.route_primary_label || label == long.route_primary_label,
        "the saved file blends two writers: {} chars",
        label.len(),
    );
    // No scratch file outlives the writes.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .expect("read dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "scratch files left behind: {leftovers:?}"
    );
}

#[test]
fn save_then_load_roundtrip_is_stable() {
    let (_dir, path) = test_path("roundtrip.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let expected = UiPreferences {
        launch_window_on_startup: false,
        minimize_to_tray_instead_of_close: true,
        show_notifications: false,
        notify_suggestion_changes: false,
        // Non-default (default is false) — proves the field persists.
        service_install_prompt_suppressed: true,
        // Non-default (default is true) — proves the field persists.
        notify_block_notices: false,
        notify_rule_duplicates: false,
        // Non-default (default is false) — proves the field persists.
        hide_block_notice_addresses: true,
        // Non-default (default is 100) — proves the field persists.
        tray_notice_opacity_percent: 80,
        reopen_last_section_on_startup: true,
        first_run_completed: true,
        accepted_eula_version: 1,
        theme_mode: ThemeMode::HighContrast,
        accessibility_high_contrast: true,
        accessibility_ui_font_scale_percent: 140,
        accessibility_system_font: SystemFontFamily::Verdana,
        accessibility_enhanced_focus_indicator: true,
        accessibility_simplified_labels: true,
        tooltips_enabled: true,
        language: "en".to_string(),
        route_primary_label: "Main".to_string(),
        route_secondary_label: "Alternative".to_string(),
        show_bluetooth_adapters: true,
        // Non-default (default is false) — proves the field persists.
        show_audit_tab: true,
        // Non-default (default is 60) — proves the field persists.
        settings_autosave_secs: 120,
        admin_auto_revoke_disabled: true,
        admin_auto_revoke_minutes: 45,
        // Non-default (default is false) — proves the field persists.
        allow_mode_a_killswitch: true,
        // Non-default (default is false) — proves the field persists.
        routing_detailed_mode: true,
        // Non-default (default is false) — proves the field persists.
        show_virtual_machines_section: true,
        // Non-default (default is false) — proves the field persists.
        app_groups_offer_dismissed: true,
        // Non-default (default is true) so the round-trip test proves the
        // field actually persists rather than reading the default.
        show_remembered_adapters: false,
        auto_confirm_adapter_id_change: false,
        // Non-default (default is true) — proves the field persists.
        warn_kill_switch_block_all: false,
        // Non-default (default is false) — proves the field persists.
        kill_switch_banner_acknowledged: true,
        // Non-default (default is false) — proves the field persists.
        missing_secondary_banner_acknowledged: true,
        // Non-default (default is "today") — proves the field persists.
        traffic_stats_period: "session".to_string(),
        // Non-default (default is "mb") — proves the field persists.
        traffic_export_unit: "gb".to_string(),
        // Non-default values (defaults: "standard" / true) — prove the
        // support-archive export options persist across save/load.
        diagnostics_archive_redaction_level: "diagnostics".to_string(),
        diagnostics_archive_session_only: false,
        // Non-default (default is 0 = unlimited) — proves the field persists.
        archive_log_budget_mib: 64,
        selected_primary_interface_id: "win-adapter:ethernet".to_string(),
        selected_primary_interface_name: "Ethernet".to_string(),
        primary_role_user_confirmed: true,
        selected_secondary_interface_id: "win-adapter:vpn".to_string(),
        selected_secondary_interface_name: "VPN".to_string(),
        secondary_role_user_confirmed: true,
        route_behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
        last_opened_section: AppSection::Settings,
        rules_view_sort: RulesViewSort::ByMatchValue,
        // Non-persisted — always resets to default on reload.
        rules_enabled_filter: RulesEnabledFilter::default(),
        rules_type_filter: RulesTypeFilter::default(),
        rules_file_change_behavior: RulesFileChangeBehavior::AutoApply,
        // File-source state. Mixed Some/None so the round-trip
        // exercises both serialise paths.
        last_saved_path_primary: Some(r"C:\rules_primary.txt".to_string()),
        last_saved_path_secondary: None,
        // Display-only source paths — a bundled-tree path is legal here
        // (read-only source), so the round-trip proves it persists.
        last_loaded_path_primary: Some(
            r"C:\Program Files\NetRuleRouter\presets\ru\pack\rules_primary.txt".to_string(),
        ),
        last_loaded_path_secondary: None,
        auto_open_on_launch_path_primary: Some(r"C:\rules_primary.txt".to_string()),
        auto_open_on_launch_path_secondary: None,
        // Exercise both serialise paths for the UAC decline state.
        service_install_uac_declined_at_epoch: Some(1_700_000_123),
        service_install_uac_declined_count: 2,
        // Non-default values so the round-trip proves they persist.
        auto_load_rules_on_launch: false,
        export_include_comments: false,
        import_only_active: false,
        compat_banner_mode: "always".to_string(),
        update_page_url: "https://example.test/releases".to_string(),
        update_check_enabled: false,
        update_check_interval_days: 30,
        dismissed_update_version: "9.9.9".to_string(),
        show_bundled_presets: false,
        // Non-default path (with spaces + backslashes) so the round-trip
        // proves the user-owned rule-set folder persists.
        user_presets_dir: "D:\\My Rule Sets".to_string(),
        // A label with a space and a colon-free body, so the round-trip
        // proves the `<source>:<label>` selection survives verbatim.
        selected_preset_set: "user:My corporate set".to_string(),
        allow_saving_into_bundled_presets: true,
        rules_folder_suggestion_dismissed: true,
        // Non-default value so the round-trip proves the merge-conflict
        // policy persists.
        merge_conflict_policy: "service-wins".to_string(),
        forward_compat: ForwardCompat::default(),
        // Non-default value so the round-trip proves the VPN-split
        // banner ack persists.
        secondary_split_ack_adapter_name: "ExampleVPN 3.0".to_string(),
        // Non-default values so the round-trip proves the per-SID
        // policy mirrors persist across save/load. Subdomain coverage
        // defaults to `true`, so `false` is the non-default value this
        // round-trip must prove persists.
        route_include_subdomains: false,
        route_shared_ip_policy: "any-rule-domain".to_string(),
        route_kill_switch_block_all: true,
        route_kill_switch_fail_closed: false,
        route_kill_switch_protocols: 123,
        route_kill_switch_enabled: true,
        // Default is true; false is the non-default value the
        // round-trip must prove persists.
        route_allow_dns_over_primary: false,
        // Non-default values (defaults: fail-closed-unknown / true) so
        // the round-trip proves these mirrors persist.
        route_mode_a_coverage_strategy: "per-ip".to_string(),
        route_resolve_hosts_bypass: false,
        route_enforcement_mode: "resolver".to_string(),
        // Non-default value inside the clamp range so the round-trip
        // proves the liveness window persists across save/load.
        route_liveness_window_secs: 90,
        // Non-empty compact JSON so the round-trip proves the
        // pending-offline intents blob persists.
        route_pending_offline_json: r#"{"killSwitchEnabled":true,"enforcementMode":"resolver"}"#
            .to_string(),
        // Cache-viewer column widths — non-empty compact JSON so the
        // round-trip proves the persisted column widths survive save/load.
        cache_table_column_widths: r#"{"ip":140,"freshness":90,"source":160}"#.to_string(),
        // Non-empty compact JSON so the round-trip proves the last-known
        // service-owned values survive save/load (the display source while
        // the service is stopped).
        service_backed_mirror_json:
            r#"{"route-policy":{"doh-lockdown-enabled":true},"stability":{"fake-ip-enabled":true}}"#
                .to_string(),
        // Non-empty compact JSON so the round-trip proves the user's
        // service-setting intent survives save/load — losing it is what
        // let a wiped service DB overwrite the user's choices.
        service_intent_json: r#"{"stability":{"verbose-logging":true,"fake-ip-enabled":true}}"#
            .to_string(),
        // Non-empty signature so the round-trip proves the
        // notification-dismiss state persists across GUI restarts.
        unenforced_apps_ack_signature: "citymap.exe|ExampleVPN 3.0.exe".to_string(),
        // Non-empty so the round-trip proves a kept overlap pair survives
        // a GUI restart.
        rules_overlap_keep_signature: "secondary:example.com>primary:api.example.com".to_string(),
        route_overlaps_confirmed_signature:
            "secondary:exact-fqdn:www.site.example>primary:zone:example".to_string(),
        // Non-empty path (with spaces + backslashes) so the round-trip
        // proves the confirmed VPN executable persists.
        confirmed_vpn_exe_path: "C:\\Program Files\\Example VPN\\vpn.exe".to_string(),
        // Non-empty semicolon-joined list so the round-trip proves the
        // multi-select VPN set persists. First entry mirrors
        // `confirmed_vpn_exe_path`.
        confirmed_vpn_exe_paths:
            "C:\\Program Files\\Example VPN\\vpn.exe;C:\\Program Files\\OpenVPN\\openvpn.exe"
                .to_string(),
    };

    store
        .save(&expected)
        .unwrap_or_else(|error| panic!("save should succeed: {error}"));
    let loaded = store
        .load()
        .unwrap_or_else(|error| panic!("load should succeed after save: {error}"));
    assert_eq!(loaded, expected);

    if path.exists() {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn cis_locales_without_bundled_translation_fall_back_to_russian() {
    // A CIS system locale with no bundled translation resolves to
    // Russian; anything else unmatched resolves to English; exact
    // matches still win.
    assert_eq!(preferred_available_language("kk-kz"), "ru");
    assert_eq!(preferred_available_language("be"), "ru");
    assert_eq!(preferred_available_language("uz-latn-uz"), "ru");
    assert_eq!(preferred_available_language("de-de"), "en");
    assert_eq!(preferred_available_language("ro-md"), "en");
    assert_eq!(preferred_available_language("ru-ru"), "ru");
    assert_eq!(preferred_available_language("en-us"), "en");
}

#[test]
fn parser_reads_block_secondary_and_rules_view_sort() {
    let parsed = parse_preferences(concat!(
        "block_secondary_traffic_when_unavailable=true\n",
        "rules_view_sort=by-match-value\n"
    ));
    assert_eq!(parsed.rules_view_sort, RulesViewSort::ByMatchValue);
    // Non-persisted filters always reset to default.
    assert_eq!(parsed.rules_enabled_filter, RulesEnabledFilter::default());
    assert_eq!(parsed.rules_type_filter, RulesTypeFilter::default());
}

#[test]
fn parser_gates_pending_offline_json_structurally() {
    // A single-line object blob is stored verbatim.
    let parsed = parse_preferences("route_pending_offline_json={\"a\":1}\n");
    assert_eq!(parsed.route_pending_offline_json, "{\"a\":1}");
    // Non-object junk is dropped (field stays at its empty default).
    let junk = parse_preferences("route_pending_offline_json=not-json\n");
    assert!(junk.route_pending_offline_json.is_empty());
    // Oversized payloads are dropped.
    let big = format!("route_pending_offline_json={{{}}}\n", "x".repeat(9000));
    assert!(parse_preferences(&big)
        .route_pending_offline_json
        .is_empty());
}

#[test]
fn selected_preset_set_remembers_the_source_it_came_from() {
    // No choice yet is the only state that lets the shipped-set list pick
    // one by system locale, so the default must be empty.
    assert!(
        UiPreferences::default().selected_preset_set.is_empty(),
        "a fresh install has no remembered rule-set choice"
    );
    // The `<source>:<label>` pair is stored verbatim — labels are folder
    // names the user controls, spaces included.
    let parsed = parse_preferences("selected_preset_set=user:My corporate set\n");
    assert_eq!(parsed.selected_preset_set, "user:My corporate set");
    // The two lists can hold identical labels, so the source prefix is what
    // keeps a remembered choice from leaking across them.
    let bundled = parse_preferences("selected_preset_set=bundled:ru_osnovnoy-i-zarubezh\n");
    assert_eq!(
        bundled.selected_preset_set,
        "bundled:ru_osnovnoy-i-zarubezh"
    );
    // Explicit empty = "forget the choice"; key absent (older preferences
    // file) falls back to the same default.
    assert!(parse_preferences("selected_preset_set=\n")
        .selected_preset_set
        .is_empty());
    assert!(parse_preferences("theme_mode=light\n")
        .selected_preset_set
        .is_empty());
}

#[test]
fn user_presets_dir_defaults_to_the_shipped_sets() {
    // Empty default = "list the sets shipped with the app".
    assert!(
        UiPreferences::default().user_presets_dir.is_empty(),
        "a fresh install must keep listing the shipped rule sets"
    );
    // A configured folder is stored verbatim, backslashes and spaces
    // included (Windows paths are the common case).
    let parsed = parse_preferences("user_presets_dir=D:\\My Rule Sets\\corp\n");
    assert_eq!(parsed.user_presets_dir, "D:\\My Rule Sets\\corp");
    // An explicit empty value is the honest "back to the shipped sets" state.
    assert!(parse_preferences("user_presets_dir=\n")
        .user_presets_dir
        .is_empty());
    // Key absent (older preferences file) falls back to the default.
    assert!(parse_preferences("theme_mode=light\n")
        .user_presets_dir
        .is_empty());
}

#[test]
fn parser_gates_service_backed_mirror_structurally() {
    // The last-known service values ride the same opaque single-line-object
    // gate: a well-formed blob is stored verbatim, junk and oversized
    // payloads are dropped rather than corrupting the line-oriented file.
    let parsed = parse_preferences(
        "service_backed_mirror_json={\"stability\":{\"fake-ip-enabled\":true}}\n",
    );
    assert_eq!(
        parsed.service_backed_mirror_json,
        "{\"stability\":{\"fake-ip-enabled\":true}}"
    );
    let junk = parse_preferences("service_backed_mirror_json=not-json\n");
    assert!(junk.service_backed_mirror_json.is_empty());
    let big = format!("service_backed_mirror_json={{{}}}\n", "x".repeat(9000));
    assert!(parse_preferences(&big)
        .service_backed_mirror_json
        .is_empty());
}

#[test]
fn parser_gates_service_intent_structurally() {
    // The user's service-setting intent rides the same opaque gate as the
    // mirror: it is replayed to the service on connect, so a corrupted
    // blob must degrade to "no intent recorded" rather than to a partial
    // object the QML side would replay as if the user had asked for it.
    let parsed =
        parse_preferences("service_intent_json={\"stability\":{\"verbose-logging\":true}}\n");
    assert_eq!(
        parsed.service_intent_json,
        "{\"stability\":{\"verbose-logging\":true}}"
    );
    let junk = parse_preferences("service_intent_json=not-json\n");
    assert!(junk.service_intent_json.is_empty());
    let big = format!("service_intent_json={{{}}}\n", "x".repeat(9000));
    assert!(parse_preferences(&big).service_intent_json.is_empty());
}

#[test]
fn parser_reads_rules_file_change_behavior() {
    let parsed = parse_preferences("rules_file_change_behavior=auto-apply\n");
    assert_eq!(
        parsed.rules_file_change_behavior,
        RulesFileChangeBehavior::AutoApply
    );
    // Default is Notify.
    let defaults = parse_preferences("");
    assert_eq!(
        defaults.rules_file_change_behavior,
        RulesFileChangeBehavior::Notify
    );
}

#[test]
fn legacy_high_contrast_flag_upgrades_theme_mode() {
    let parsed = parse_preferences(concat!(
        "theme_mode=light\n",
        "accessibility_high_contrast=true\n"
    ));
    assert_eq!(parsed.theme_mode, ThemeMode::HighContrast);
    assert!(parsed.accessibility_high_contrast);
}

#[test]
fn schema_version_constant_is_current() {
    // Each schema bump is additive: older files load with the new
    // fields defaulted via the "missing key → default" path in
    // `parse_preferences`.
    assert_eq!(CURRENT_UI_PREFS_SCHEMA_VERSION, 12);
}

#[test]
fn a_newer_files_unknown_settings_survive_a_save_by_this_build() {
    let future = CURRENT_UI_PREFS_SCHEMA_VERSION + 3;
    let content = format!(
        "schema_version={future}\ntheme_mode=dark\nsomething_from_the_future=42\n\
             another_future_key=on\n"
    );

    let parsed = parse_preferences(&content);
    assert_eq!(parsed.forward_compat.newer_schema_version, Some(future));
    assert_eq!(
        parsed.forward_compat.unknown_lines,
        vec![
            "something_from_the_future=42".to_string(),
            "another_future_key=on".to_string(),
        ]
    );

    // Saving must neither drop those settings nor lower the stamp: the next
    // start of the newer build has to find its own file intact.
    let rendered = format_preferences(&parsed);
    assert!(rendered.contains(&format!("schema_version={future}\n")));
    assert!(rendered.contains("something_from_the_future=42\n"));
    assert!(rendered.contains("another_future_key=on\n"));
    assert_eq!(
        parse_preferences(&rendered).forward_compat,
        parsed.forward_compat
    );
}

#[test]
fn route_labels_follow_the_chosen_language_not_the_system_one() {
    // A file from before the labels existed carries `language=` and no
    // labels. Deriving them from the system language is how a Russian-UI
    // user ended up with "Primary"/"Secondary".
    let parsed = parse_preferences("language=ru\ntheme_mode=dark\n");
    assert_eq!(parsed.route_primary_label, "Основной");
    assert_eq!(parsed.route_secondary_label, "Дополнительный");

    // Labels the user actually set are never recomputed.
    let parsed = parse_preferences("language=ru\nroute_primary_label=Дом\n");
    assert_eq!(parsed.route_primary_label, "Дом");
}

#[test]
fn a_file_that_names_its_language_never_asks_the_system() {
    let asked = std::cell::Cell::new(0u32);
    let probe = || {
        asked.set(asked.get() + 1);
        "en".to_string()
    };
    let parsed = super::parse_preferences_with("language=ru\ntheme_mode=dark\n", probe);
    assert_eq!(asked.get(), 0);
    assert_eq!(parsed.language, "ru");
    assert_eq!(parsed.route_secondary_label, "Дополнительный");
}

#[test]
fn a_file_without_a_language_asks_the_system_once() {
    let asked = std::cell::Cell::new(0u32);
    let probe = || {
        asked.set(asked.get() + 1);
        "ru".to_string()
    };
    let parsed = super::parse_preferences_with("theme_mode=dark\nroute_primary_label=Дом\n", probe);
    assert_eq!(asked.get(), 1);
    assert_eq!(parsed.language, "ru");
    assert_eq!(parsed.route_primary_label, "Дом");
    assert_eq!(parsed.route_secondary_label, "Дополнительный");
}

#[test]
fn the_system_language_comes_from_the_port_unless_overridden() {
    use nrr_platform_api::system_locale::SystemLocalePort;

    struct Counting(std::sync::atomic::AtomicU32, Option<&'static str>);
    impl SystemLocalePort for Counting {
        fn ui_language_candidates(&self) -> Vec<String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.1.map(str::to_string).into_iter().collect()
        }
    }
    let calls = |port: &Counting| port.0.load(std::sync::atomic::Ordering::Relaxed);

    let russian = Counting(Default::default(), Some("ru-RU"));
    assert_eq!(
        super::detect_system_language_with(None, Some(&russian)),
        "ru"
    );
    assert_eq!(calls(&russian), 1);

    // The product override outranks the OS and spares the probe.
    let untouched = Counting(Default::default(), Some("ru-RU"));
    assert_eq!(
        super::detect_system_language_with(Some("en_US.UTF-8"), Some(&untouched)),
        "en"
    );
    assert_eq!(calls(&untouched), 0);

    // A host that cannot tell, or no probe at all, lands on English.
    let silent = Counting(Default::default(), None);
    assert_eq!(
        super::detect_system_language_with(None, Some(&silent)),
        "en"
    );
    assert_eq!(super::detect_system_language_with(None, None), "en");
}

/// A candidate list of one, standing for what a real port returns: on
/// Windows, either the UI language or (only when that could not be read at
/// all) the regional-format locale — never both.
struct FixedCandidates(&'static [&'static str]);
impl nrr_platform_api::system_locale::SystemLocalePort for FixedCandidates {
    fn ui_language_candidates(&self) -> Vec<String> {
        self.0.iter().map(|item| item.to_string()).collect()
    }
}

#[test]
fn an_untranslated_ui_language_falls_to_english_not_the_regional_format() {
    // The Windows port never offers the regional-format locale alongside a
    // readable UI language, so a single "de" candidate is what it looks
    // like when the interface language is German but Windows' regional
    // format is Russian: the owner's 29.09 decision is that the regional
    // format must not stand in for the untranslated "de".
    assert_eq!(
        super::detect_system_language_with(None, Some(&FixedCandidates(&["de"]))),
        "en"
    );
}

#[test]
fn a_translated_ui_language_is_used_as_is() {
    assert_eq!(
        super::detect_system_language_with(None, Some(&FixedCandidates(&["ru"]))),
        "ru"
    );
}

#[test]
fn an_unreadable_ui_language_falls_to_the_regional_format() {
    // Stands in for Windows when the UI language truly could not be read:
    // the port's only candidate is then the regional-format locale, and
    // that candidate is used exactly like any other.
    assert_eq!(
        super::detect_system_language_with(None, Some(&FixedCandidates(&["ru-RU"]))),
        "ru"
    );
}

#[test]
fn a_linux_language_list_is_walked_to_the_first_translated_entry() {
    // `LANGUAGE=de:ru:en` — German has no bundled translation, so the walk
    // continues to Russian rather than stopping at the untranslated head or
    // jumping straight to English.
    assert_eq!(
        super::detect_system_language_with(None, Some(&FixedCandidates(&["de", "ru", "en"]))),
        "ru"
    );
}

#[test]
fn the_override_still_outranks_every_port_candidate() {
    assert_eq!(
        super::detect_system_language_with(Some("ru"), Some(&FixedCandidates(&["de", "en"]))),
        "ru"
    );
}

#[test]
fn repeated_language_lookups_read_the_locale_catalog_once() {
    use std::sync::atomic::Ordering;
    // Whatever this process already cached, one more lookup settles it (if
    // it had not already) and no further lookup re-reads or re-validates
    // the locales directory.
    let _ = super::preferred_available_language("ru");
    let after_first = super::LOCALE_CATALOG_READS.load(Ordering::Relaxed);
    let _ = super::preferred_available_language("de");
    let _ = super::detect_system_language_with(None, Some(&FixedCandidates(&["fr"])));
    let after_more = super::LOCALE_CATALOG_READS.load(Ordering::Relaxed);
    assert_eq!(
        after_more, after_first,
        "the locale catalog must be read at most once per process"
    );
}

#[test]
fn a_language_no_catalog_carries_resolves_instead_of_being_stored() {
    assert_eq!(parse_preferences("language=zz\n").language, "en");
    assert_eq!(parse_preferences("language=ru-RU\n").language, "ru");
}

#[test]
fn out_of_range_numbers_clamp_and_garbage_keeps_the_current_value() {
    // Reverting to the default moved a security-relevant timer to a number
    // nobody chose; the range ends are what the user actually asked for.
    let parsed = parse_preferences("admin_auto_revoke_minutes=9999\n");
    assert_eq!(
        parsed.admin_auto_revoke_minutes,
        ADMIN_AUTO_REVOKE_MAX_MINUTES
    );
    let parsed = parse_preferences("admin_auto_revoke_minutes=0\n");
    assert_eq!(
        parsed.admin_auto_revoke_minutes,
        ADMIN_AUTO_REVOKE_MIN_MINUTES
    );
    let parsed = parse_preferences("settings_autosave_secs=1\n");
    assert_eq!(parsed.settings_autosave_secs, SETTINGS_AUTOSAVE_MIN_SECS);

    // Unparseable is not a value at all — keep what is already there.
    let parsed = parse_preferences("admin_auto_revoke_minutes=abc\n");
    assert_eq!(
        parsed.admin_auto_revoke_minutes,
        UiPreferences::default().admin_auto_revoke_minutes
    );
}

#[test]
fn a_stored_update_check_interval_snaps_to_an_offered_choice() {
    assert_eq!(UiPreferences::default().update_check_interval_days, 14);
    for (stored, read) in [
        (0, 7),
        (1, 7),
        (7, 7),
        (10, 7),
        (14, 14),
        (29, 14),
        (30, 30),
        (365, 30),
    ] {
        let parsed = parse_preferences(&format!("update_check_interval_days={stored}\n"));
        assert_eq!(parsed.update_check_interval_days, read, "stored {stored}");
    }
    let parsed = parse_preferences("update_check_interval_days=weekly\n");
    assert_eq!(
        parsed.update_check_interval_days, 14,
        "unparseable keeps the default"
    );
}

#[test]
fn a_signature_past_the_ceiling_keeps_the_stored_one() {
    let oversized = "a".repeat(MAX_STORED_STRING_BYTES + 1);
    let parsed = parse_preferences(&format!("unenforced_apps_ack_signature={oversized}\n"));
    // Refused, not truncated: half a signature matches nothing but still
    // looks like an answer.
    assert!(parsed.unenforced_apps_ack_signature.is_empty());

    let at_ceiling = "b".repeat(MAX_STORED_STRING_BYTES);
    let parsed = parse_preferences(&format!("unenforced_apps_ack_signature={at_ceiling}\n"));
    assert_eq!(parsed.unenforced_apps_ack_signature, at_ceiling);
}

#[test]
fn every_stored_blob_passes_the_same_gate() {
    // The gate lived in five hand-copied places; the risk was one of them
    // drifting. This pins all four keys to the single declaration.
    let oversized = format!("{{{}}}", "x".repeat(MAX_STORED_JSON_BLOB_BYTES));
    let content = format!(
        "route_pending_offline_json={{\"a\":1}}\n\
             cache_table_column_widths=not-an-object\n\
             service_backed_mirror_json={oversized}\n\
             service_intent_json={{\"mode\":\"resolver\"}}\n"
    );
    let parsed = parse_preferences(&content);

    assert_eq!(parsed.route_pending_offline_json, "{\"a\":1}");
    assert_eq!(parsed.service_intent_json, "{\"mode\":\"resolver\"}");
    assert!(parsed.cache_table_column_widths.is_empty());
    assert!(parsed.service_backed_mirror_json.is_empty());
}

/// Keys are added without a schema bump, so a build of the same version that
/// predates a key must not erase it by saving over the file.
#[test]
fn an_unknown_key_in_a_current_file_survives_load_and_save() {
    let (_dir, path) = test_path("same-version-unknown-key.conf");
    fs::write(
        &path,
        format!(
            "schema_version={CURRENT_UI_PREFS_SCHEMA_VERSION}\ntheme_mode=dark\n\
             key_added_by_a_later_build=true\n"
        ),
    )
    .unwrap_or_else(|e| panic!("write: {e}"));
    let store = UiPreferencesStore::for_path(path.clone());
    let loaded = store.load().unwrap_or_else(|e| panic!("load: {e}"));
    assert_eq!(loaded.forward_compat.newer_schema_version, None);
    store.save(&loaded).unwrap_or_else(|e| panic!("save: {e}"));

    let saved = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read: {e}"));
    assert!(
        saved.contains("key_added_by_a_later_build=true\n"),
        "{saved}"
    );
    assert!(saved.contains(&format!(
        "schema_version={CURRENT_UI_PREFS_SCHEMA_VERSION}\n"
    )));
}

/// Removing a key bumps the schema, so in an older file an unknown key is the
/// residue of one, and it must not live forever.
#[test]
fn an_unknown_key_in_an_older_file_is_dropped_not_carried() {
    let older = CURRENT_UI_PREFS_SCHEMA_VERSION - 1;
    for content in [
        format!("schema_version={older}\ntheme_mode=dark\nretired_key=1\n"),
        "theme_mode=dark\nretired_key=1\n".to_string(),
    ] {
        let parsed = parse_preferences(&content);
        assert_eq!(parsed.forward_compat, ForwardCompat::default());
        assert!(!format_preferences(&parsed).contains("retired_key"));
    }
}

#[test]
fn schema_version_written_on_save_is_parsed_without_panic() {
    // Verify that a freshly saved file has schema_version and loads back cleanly.
    let (_dir, path) = test_path("schema-version-roundtrip.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let prefs = UiPreferences::default();
    store
        .save(&prefs)
        .unwrap_or_else(|e| panic!("save should succeed: {e}"));
    let content = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read should succeed: {e}"));
    let expected_version = format!("schema_version={CURRENT_UI_PREFS_SCHEMA_VERSION}");
    assert!(
        content.contains(&expected_version),
        "saved file must contain {expected_version}; got:\n{content}"
    );
    // A file of our own version carries nothing forward.
    assert_eq!(
        parse_preferences(&content).forward_compat,
        ForwardCompat::default()
    );
    // `_dir` drops here, removing the scratch directory and the conf file
    // together — no manual `fs::remove_file` needed.
}

/// A v1 preference file must load with the new fields all set to
/// `None`. This is the migration-tolerant path: a schema bump
/// doesn't require touching old files; missing keys parse as field
/// defaults via the catch-all `_ => {}` arm in `parse_preferences`.
#[test]
fn v1_file_without_new_fields_loads_with_defaults() {
    let legacy_v1 = "\
schema_version=1
theme_mode=dark
language=ru
first_run_completed=true
";
    let parsed = parse_preferences(legacy_v1);
    // Fields present in the legacy file populate as expected.
    assert_eq!(parsed.theme_mode, ThemeMode::Dark);
    assert_eq!(parsed.language, "ru");
    assert!(parsed.first_run_completed);
    // Fields absent from the legacy file all default to None.
    assert!(parsed.last_saved_path_primary.is_none());
    assert!(parsed.last_saved_path_secondary.is_none());
    assert!(parsed.auto_open_on_launch_path_primary.is_none());
    assert!(parsed.auto_open_on_launch_path_secondary.is_none());
}

/// Empty value parses as `None` (sentinel for "not recorded"),
/// matching the format-side convention.
#[test]
fn empty_value_for_optional_string_parses_as_none() {
    let input = "last_saved_path_primary=\nlast_saved_path_secondary=\n";
    let parsed = parse_preferences(input);
    assert!(parsed.last_saved_path_primary.is_none());
    assert!(parsed.last_saved_path_secondary.is_none());
}

#[test]
fn nonempty_value_for_optional_string_parses_as_some() {
    let input = "last_saved_path_primary=C:\\rules_primary.txt\n";
    let parsed = parse_preferences(input);
    assert_eq!(
        parsed.last_saved_path_primary.as_deref(),
        Some("C:\\rules_primary.txt")
    );
}

/// A v2 preference file must load with the two UAC-state fields
/// defaulting to their zero values. Missing keys parse via the
/// catch-all `_ => {}` arm and the struct's `Default` impl fills the
/// holes.
#[test]
fn v2_file_without_new_fields_loads_with_defaults() {
    let legacy_v2 = "\
schema_version=2
theme_mode=dark
language=ru
first_run_completed=true
last_saved_path_primary=C:\\rules_primary.txt
";
    let parsed = parse_preferences(legacy_v2);
    assert_eq!(parsed.theme_mode, ThemeMode::Dark);
    assert_eq!(parsed.language, "ru");
    assert!(parsed.first_run_completed);
    assert_eq!(
        parsed.last_saved_path_primary.as_deref(),
        Some("C:\\rules_primary.txt")
    );
    assert!(parsed.service_install_uac_declined_at_epoch.is_none());
    assert_eq!(parsed.service_install_uac_declined_count, 0);
    // Newer toggles default (auto-load + comments ON, banner auto, no
    // custom URL) even though the v2 file omits them.
    assert!(parsed.auto_load_rules_on_launch);
    assert!(parsed.export_include_comments);
    assert_eq!(parsed.compat_banner_mode, "auto");
    assert!(parsed.update_page_url.is_empty());
}

/// A v3 file (UAC fields present, newer toggles absent) loads the
/// toggles at their `true`/`auto`/empty defaults, and an unknown
/// `compat_banner_mode` slug falls back to the default rather than
/// corrupting the value.
#[test]
fn v3_file_without_new_toggles_loads_with_defaults() {
    let legacy_v3 = "\
schema_version=3
theme_mode=dark
service_install_uac_declined_count=1
";
    let parsed = parse_preferences(legacy_v3);
    assert_eq!(parsed.service_install_uac_declined_count, 1);
    assert!(parsed.auto_load_rules_on_launch);
    assert!(parsed.export_include_comments);
    assert_eq!(parsed.compat_banner_mode, "auto");
    assert!(parsed.update_page_url.is_empty());
}

#[test]
fn unknown_compat_banner_mode_falls_back_to_default() {
    let parsed = parse_preferences("compat_banner_mode=bogus\n");
    assert_eq!(parsed.compat_banner_mode, "auto");
    let ok = parse_preferences("compat_banner_mode=never\n");
    assert_eq!(ok.compat_banner_mode, "never");
}

/// The store owns the allow-list for the support-archive privacy tier: a
/// hand-edited or unknown slug must not leave the exporter pointing at a
/// tier it cannot produce.
#[test]
fn unknown_diagnostics_archive_redaction_level_falls_back_to_default() {
    let parsed = parse_preferences("diagnostics_archive_redaction_level=everything\n");
    assert_eq!(
        parsed.diagnostics_archive_redaction_level,
        crate::ui_preferences::DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT
    );
    let ok = parse_preferences("diagnostics_archive_redaction_level=diagnostics\n");
    assert_eq!(ok.diagnostics_archive_redaction_level, "diagnostics");
}

/// Empty value for `service_install_uac_declined_at_epoch` parses as
/// `None`. Non-empty value parses as `Some(i64)`.
#[test]
fn empty_uac_declined_at_epoch_parses_as_none() {
    let input = "service_install_uac_declined_at_epoch=\n";
    let parsed = parse_preferences(input);
    assert!(parsed.service_install_uac_declined_at_epoch.is_none());
}

#[test]
fn nonempty_uac_declined_at_epoch_parses_as_some() {
    let input =
        "service_install_uac_declined_at_epoch=1700000123\nservice_install_uac_declined_count=2\n";
    let parsed = parse_preferences(input);
    assert_eq!(
        parsed.service_install_uac_declined_at_epoch,
        Some(1_700_000_123)
    );
    assert_eq!(parsed.service_install_uac_declined_count, 2);
}

#[test]
fn legacy_v0_file_loads_without_schema_version_field() {
    // A file written before schema_version was introduced must load cleanly.
    let parsed = parse_preferences("theme_mode=dark\nlanguage=ru\n");
    assert_eq!(parsed.theme_mode, ThemeMode::Dark);
    assert_eq!(parsed.language, "ru");
    // An absent key is a legacy v0 file: nothing to carry, no warning.
    assert!(declared_schema_version("theme_mode=dark\nlanguage=ru\n").is_none());
    assert_eq!(parsed.forward_compat, ForwardCompat::default());
}

#[test]
fn parser_accepts_schema_version_key_without_affecting_preferences() {
    let parsed = parse_preferences("schema_version=1\ntheme_mode=dark\nlanguage=en\n");
    assert_eq!(parsed.theme_mode, ThemeMode::Dark);
    assert_eq!(parsed.language, "en");
}

/// Allocate a fresh scratch path under a `TempDir`. The caller MUST keep
/// the returned `TempDir` binding alive — dropping it removes the
/// directory recursively, so no test invocation leaks a scratch
/// directory.
fn test_path(file_name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = test_dir("files");
    let path = dir.path().join(file_name);
    (dir, path)
}

#[test]
fn a_gutted_primary_file_recovers_from_the_backup() {
    // A power cut can commit the rename while the data blocks are still
    // unflushed: the primary survives as an empty (or NUL-filled) husk.
    let (_dir, path) = test_path("gutted.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let expected = UiPreferences {
        theme_mode: ThemeMode::Light,
        first_run_completed: true,
        ..UiPreferences::default()
    };
    store.save(&expected).expect("first save");
    store
        .save(&expected)
        .expect("second save writes the backup");

    for husk in ["", "\0\0\0\0", "# NetRuleRouter managed UI preferences\n"] {
        fs::write(&path, husk).expect("plant the husk");
        let loaded = store.load().expect("load must recover");
        assert!(
            loaded.first_run_completed,
            "husk {husk:?} must fall back to the backup, not to defaults"
        );
        assert_eq!(loaded.theme_mode, ThemeMode::Light);
    }
}

#[test]
fn a_missing_primary_file_recovers_from_the_backup() {
    let (_dir, path) = test_path("missing.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let expected = UiPreferences {
        accepted_eula_version: 1,
        ..UiPreferences::default()
    };
    store.save(&expected).expect("first save");
    store
        .save(&expected)
        .expect("second save writes the backup");
    fs::remove_file(&path).expect("drop the primary");

    let loaded = store.load().expect("load must recover");
    assert_eq!(loaded.accepted_eula_version, 1);
}

#[test]
fn a_gutted_primary_never_overwrites_a_good_backup() {
    // After the husk was loaded as defaults, the very next save must not
    // copy the husk over the last good backup.
    let (_dir, path) = test_path("preserve-bak.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let good = UiPreferences {
        first_run_completed: true,
        ..UiPreferences::default()
    };
    store.save(&good).expect("first save");
    store.save(&good).expect("second save writes the backup");

    fs::write(&path, "").expect("plant the husk");
    store
        .save(&UiPreferences::default())
        .expect("save over the husk");
    let backup = fs::read_to_string(path.with_extension("bak")).expect("backup exists");
    assert!(
        backup.contains("first_run_completed=true"),
        "the good backup must survive a save over a gutted primary"
    );
}

fn with_trailing_keys(eula: u32) -> UiPreferences {
    UiPreferences {
        accepted_eula_version: eula,
        first_run_completed: true,
        service_intent_json: r#"{"intent":"keep"}"#.to_string(),
        selected_primary_interface_id: "adapter-a".to_string(),
        ..UiPreferences::default()
    }
}

#[test]
fn a_save_stopped_after_staging_leaves_the_old_primary() {
    let (_dir, path) = test_path("stop-after-stage.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    store.save(&with_trailing_keys(1)).expect("first save");
    let before = fs::read(&path).expect("primary");

    let _staged = store.stage(&with_trailing_keys(2)).expect("stage");

    assert_eq!(fs::read(&path).expect("primary"), before);
    assert_eq!(store.load().expect("load"), with_trailing_keys(1));
}

#[test]
fn a_save_stopped_between_the_renames_leaves_a_whole_backup() {
    let (_dir, path) = test_path("stop-between-renames.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    store.save(&with_trailing_keys(1)).expect("first save");
    let before = fs::read(&path).expect("primary");

    let _staged = store.stage(&with_trailing_keys(2)).expect("stage");
    store.retire_primary_to_backup();

    assert!(!path.exists(), "the primary moved, it was not copied");
    assert_eq!(
        fs::read(path.with_extension("bak")).expect("backup"),
        before,
        "the backup is the old primary byte for byte, trailing keys included"
    );
    let reopened = UiPreferencesStore::for_path(path.clone());
    assert_eq!(reopened.load().expect("load"), with_trailing_keys(1));
}

#[test]
fn a_completed_save_keeps_the_previous_file_as_the_backup() {
    let (_dir, path) = test_path("complete.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    store.save(&with_trailing_keys(1)).expect("first save");
    let first = fs::read(&path).expect("primary");
    store.save(&with_trailing_keys(2)).expect("second save");

    assert_eq!(fs::read(path.with_extension("bak")).expect("backup"), first);
    assert_eq!(store.load().expect("load"), with_trailing_keys(2));
}

#[test]
fn a_husk_primary_leaves_the_good_backup_byte_for_byte() {
    let (_dir, path) = test_path("husk-keeps-bak.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    store.save(&with_trailing_keys(1)).expect("first save");
    store
        .save(&with_trailing_keys(1))
        .expect("second save writes the backup");
    let good_backup = fs::read(path.with_extension("bak")).expect("backup");

    fs::write(&path, "\0\0\0\0").expect("plant the husk");
    store
        .save(&with_trailing_keys(3))
        .expect("save over the husk");

    assert_eq!(
        fs::read(path.with_extension("bak")).expect("backup"),
        good_backup
    );
    assert_eq!(store.load().expect("load"), with_trailing_keys(3));
}

#[test]
fn first_launch_with_no_files_still_defaults() {
    let (_dir, path) = test_path("fresh.conf");
    let store = UiPreferencesStore::for_path(path);
    let loaded = store.load().expect("fresh load");
    assert!(!loaded.first_run_completed);
}

/// A write error after the scratch file was created must not orphan it: the
/// forced failure fires only after `File::create` succeeds, so a leftover
/// here would be a real regression, not a creation that never happened.
#[test]
fn stage_removes_its_scratch_file_when_the_write_fails() {
    let (_dir, path) = test_path("stage-write-fails.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    let parent = path.parent().expect("parent").to_path_buf();

    crate::ui_preferences::store::FORCE_NEXT_STAGE_WRITE_FAILURE.with(|flag| flag.set(true));
    let result = store.stage(&UiPreferences::default());

    assert!(result.is_err(), "the forced failure must surface");
    let leftovers: Vec<_> = fs::read_dir(&parent)
        .expect("read the scratch directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "a failed stage must not leave a scratch file behind: {leftovers:?}"
    );
}

/// `.tmp` scratch files older than the sweep floor are this store's own
/// litter (a crash before `commit`, or a write error before the cleanup
/// above existed) and must go; a fresh one — another writer's in-flight
/// save — and files that are not this store's scratch shape must survive.
#[test]
fn save_sweeps_only_its_own_stale_scratch_files() {
    let (_dir, path) = test_path("sweep.conf");
    let store = UiPreferencesStore::for_path(path.clone());
    fs::create_dir_all(path.parent().expect("parent")).expect("scratch dir");

    let stale = path.with_extension("123-0.tmp");
    let fresh = path.with_extension("456-0.tmp");
    let unrelated = path.with_extension("bak");
    for scratch in [&stale, &fresh, &unrelated] {
        fs::write(scratch, b"leftover").expect("plant a file");
    }
    let far_past = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    set_file_mtime(&stale, far_past);

    store.save(&UiPreferences::default()).expect("save");

    assert!(!stale.exists(), "a stale scratch file must be swept");
    assert!(
        fresh.exists(),
        "a fresh scratch file is not this save's to remove"
    );
    assert!(
        unrelated.exists(),
        "a non-scratch sibling must never be touched"
    );
}

fn set_file_mtime(path: &std::path::Path, when: std::time::SystemTime) {
    let file = fs::File::options()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(when).expect("backdate mtime");
}

fn test_dir(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(&format!("nrr-ui-preferences-tests-{prefix}-"))
        .tempdir()
        .unwrap_or_else(|error| panic!("failed to create temp dir: {error}"))
}

/// A protocol mask that blocks nothing must not be stored or masked into
/// meaning (`128 & 0x7F` is zero, "Other" alone cuts nothing): the value is
/// seeded back into the service after its database is cleared, and the service
/// refuses such a mask.
#[test]
fn a_nonsense_protocol_mask_keeps_the_default_instead_of_disarming() {
    let default = UiPreferences::default().route_kill_switch_protocols;
    assert_eq!(default, 127);
    for garbage in ["0", "64", "128", "256", "4294967295", "-1", "seven", ""] {
        let parsed = parse_preferences(&format!("route_kill_switch_protocols={garbage}\n"));
        assert_eq!(
            parsed.route_kill_switch_protocols, default,
            "{garbage:?} must not redefine the protocol mask",
        );
    }
    for kept in ["1", "5", "127"] {
        let parsed = parse_preferences(&format!("route_kill_switch_protocols={kept}\n"));
        assert_eq!(parsed.route_kill_switch_protocols.to_string(), kept);
    }
}

/// A slug off its list keeps the default: an underscore spelling of a shared-IP
/// policy was stored as-is and refused by `route.policy.update` on the reseed.
#[test]
fn policy_and_period_slugs_off_their_lists_keep_the_default() {
    let default = UiPreferences::default();
    for garbage in ["majority_of_ip", "MAJORITY-OF-IP", "none", ""] {
        let parsed = parse_preferences(&format!("route_shared_ip_policy={garbage}\n"));
        assert_eq!(
            parsed.route_shared_ip_policy, default.route_shared_ip_policy,
            "{garbage:?}"
        );
    }
    for garbage in ["yesterday", "all_time", ""] {
        let parsed = parse_preferences(&format!("traffic_stats_period={garbage}\n"));
        assert_eq!(
            parsed.traffic_stats_period, default.traffic_stats_period,
            "{garbage:?}"
        );
    }
    for slug in super::SHARED_IP_POLICIES {
        let parsed = parse_preferences(&format!("route_shared_ip_policy={slug}\n"));
        assert_eq!(parsed.route_shared_ip_policy, slug);
    }
    for slug in super::TRAFFIC_STATS_PERIODS {
        let parsed = parse_preferences(&format!("traffic_stats_period={slug}\n"));
        assert_eq!(parsed.traffic_stats_period, slug);
    }
    assert!(super::SHARED_IP_POLICIES.contains(&default.route_shared_ip_policy.as_str()));
    assert!(super::TRAFFIC_STATS_PERIODS.contains(&default.traffic_stats_period.as_str()));
}

#[test]
fn a_parked_intent_past_its_window_does_not_survive_the_load() {
    let day_ms = 24 * 60 * 60 * 1000_i64;
    let prefs = UiPreferences {
        route_pending_offline_json: r#"{"parked-at-ms":1000,"route-policy":{"kill-switch":true}}"#
            .to_string(),
        ..UiPreferences::default()
    };

    let fresh = without_expired_parked_intents(prefs.clone(), 1000 + day_ms);
    assert!(
        !fresh.route_pending_offline_json.is_empty(),
        "a day-old intent is still the decision the user made"
    );

    let stale = without_expired_parked_intents(prefs, 1000 + 8 * day_ms);
    assert!(
        stale.route_pending_offline_json.is_empty(),
        "a week-old 'block everything' must not land on the next connect"
    );
}
