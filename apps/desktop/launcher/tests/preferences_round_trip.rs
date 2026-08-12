#![allow(clippy::expect_used)]

//! Verifies the QML→launcher preferences round-trip used to persist UI
//! state across runs. The QML side emits a `NRR_PREFS_JSON:<payload>` line
//! to stdout whenever `emitPrefs()` fires; the launcher's
//! `apply_qt_preferences_payload` parses the latest payload and reconciles
//! it with the in-memory baseline before persisting through
//! `nrr-ui-support`.
//!
//! The regression we are guarding against: switching themes from `system`
//! to `dark` (or `high-contrast`) used to silently revert because the
//! launcher's stub had not been replaced with the real parser.

use nrr_launcher::apply_qt_preferences_payload;
use nrr_shared::ThemeMode;
use nrr_ui_support::ui_preferences::UiPreferences;

fn payload_with_theme(theme_mode: &str, accessibility_high_contrast: bool) -> String {
    let mut object = serde_json::Map::new();
    object.insert("launchWindowOnStartup".into(), true.into());
    object.insert("minimizeToTrayInsteadOfClose".into(), true.into());
    object.insert("showNotifications".into(), true.into());
    object.insert("reopenLastSectionOnStartup".into(), true.into());
    object.insert("firstRunCompleted".into(), true.into());
    object.insert("themeMode".into(), theme_mode.into());
    object.insert(
        "accessibilityHighContrast".into(),
        accessibility_high_contrast.into(),
    );
    object.insert("fontScalePercent".into(), 100u64.into());
    object.insert("systemFont".into(), "system-default".into());
    object.insert("enhancedFocus".into(), false.into());
    object.insert("simplifiedLabels".into(), false.into());
    object.insert("tooltipsEnabled".into(), true.into());
    object.insert("language".into(), "en".into());
    object.insert("routePrimaryLabel".into(), "Primary".into());
    object.insert("routeSecondaryLabel".into(), "Secondary".into());
    object.insert("selectedPrimaryInterfaceName".into(), "".into());
    object.insert("selectedSecondaryInterfaceName".into(), "".into());
    // Valid RouteBehaviorMode slug; "auto" was never a variant and
    // silently failed to parse.
    object.insert("routeBehaviorMode".into(), "prefer-primary".into());
    object.insert("lastOpenedSection".into(), "interfaces-routes".into());
    serde_json::Value::Object(object).to_string()
}

#[test]
fn dark_theme_round_trips_through_payload() {
    let baseline = UiPreferences::default();
    let dark_payload = payload_with_theme("dark", false);
    let updated =
        apply_qt_preferences_payload(&baseline, &dark_payload).expect("dark payload must parse");
    assert_eq!(updated.theme_mode, ThemeMode::Dark);
    assert!(!updated.accessibility_high_contrast);
}

#[test]
fn light_theme_round_trips_through_payload() {
    let baseline = UiPreferences::default();
    let light_payload = payload_with_theme("light", false);
    let updated =
        apply_qt_preferences_payload(&baseline, &light_payload).expect("light payload must parse");
    assert_eq!(updated.theme_mode, ThemeMode::Light);
}

#[test]
fn system_theme_round_trips_through_payload() {
    let baseline = UiPreferences::default();
    let system_payload = payload_with_theme("system", false);
    let updated = apply_qt_preferences_payload(&baseline, &system_payload)
        .expect("system payload must parse");
    assert_eq!(updated.theme_mode, ThemeMode::System);
}

#[test]
fn high_contrast_flag_pins_theme_mode() {
    let baseline = UiPreferences::default();
    // Even if the payload reports themeMode=light, the explicit
    // accessibilityHighContrast=true flag must override and pin the mode.
    let payload = payload_with_theme("light", true);
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("high-contrast payload must parse");
    assert_eq!(updated.theme_mode, ThemeMode::HighContrast);
    assert!(updated.accessibility_high_contrast);
}

#[test]
fn route_policy_mirrors_round_trip_through_payload() {
    // The master kill-switch toggle, the DNS-over-primary opt-in, and
    // subdomain coverage are device-local mirrors that must survive a GUI
    // restart (and re-seed the service after a state-DB wipe). Regression
    // guard: `routeKillSwitchEnabled` / `routeAllowDnsOverPrimary` were
    // absent from the QtPreferencesPayload parse, so QML emitted them but
    // the launcher silently dropped them and the toggles never persisted.
    let baseline = UiPreferences::default();
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    // Subdomain coverage defaults ON, so `false` is the non-default value
    // that proves the mirror actually round-trips.
    object.insert("routeIncludeSubdomains".into(), false.into());
    object.insert("routeKillSwitchEnabled".into(), true.into());
    object.insert("routeAllowDnsOverPrimary".into(), true.into());
    object.insert("routeKillSwitchBlockAll".into(), true.into());
    // Non-default values (defaults: fail-closed-unknown / true).
    object.insert("routeModeACoverageStrategy".into(), "per-ip".into());
    object.insert("routeResolveHostsBypass".into(), false.into());
    let payload = serde_json::Value::Object(object).to_string();
    let updated =
        apply_qt_preferences_payload(&baseline, &payload).expect("route mirror payload must parse");
    assert!(
        !updated.route_include_subdomains,
        "subdomain coverage must round-trip"
    );
    assert!(
        updated.route_kill_switch_enabled,
        "master kill-switch toggle must round-trip"
    );
    assert!(
        updated.route_allow_dns_over_primary,
        "DNS-over-primary opt-in must round-trip"
    );
    assert!(updated.route_kill_switch_block_all);
    assert_eq!(
        updated.route_mode_a_coverage_strategy, "per-ip",
        "Mode-A coverage strategy must round-trip"
    );
    assert!(
        !updated.route_resolve_hosts_bypass,
        "hosts-bypass opt-out must round-trip"
    );
}

#[test]
fn pending_offline_intents_round_trip_through_payload() {
    // The offline-intents blob must survive GUI→launcher parse. Regression
    // guard: `routePendingOfflineJson` was dropped from the
    // QtPreferencesPayload parse, so the "apply changes made while the
    // service was stopped?" dialog would never fire — the whole feature
    // was a silent no-op and every gate still passed. Assert BOTH
    // directions: a valid `{…}` blob round-trips, and an empty string
    // clears (applied/discarded).
    let baseline = UiPreferences::default();
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert(
        "routePendingOfflineJson".into(),
        serde_json::json!(r#"{"route-policy":{"kill-switch-enabled":true}}"#),
    );
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("pending-offline payload must parse");
    assert_eq!(
        updated.route_pending_offline_json, r#"{"route-policy":{"kill-switch-enabled":true}}"#,
        "a valid pending-offline blob must round-trip through the launcher parse"
    );

    // Empty string (applied/discarded) clears the stored value.
    let started = UiPreferences {
        route_pending_offline_json: r#"{"a":1}"#.to_string(),
        ..UiPreferences::default()
    };
    let mut object2: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object2.insert("routePendingOfflineJson".into(), serde_json::json!(""));
    let cleared =
        apply_qt_preferences_payload(&started, &serde_json::Value::Object(object2).to_string())
            .expect("clear payload must parse");
    assert!(
        cleared.route_pending_offline_json.is_empty(),
        "an empty blob must clear the stored pending set"
    );
}

#[test]
fn service_backed_mirror_round_trips_through_payload() {
    // The GUI mirrors the last-known values of the settings the service owns so
    // a service-stopped launch shows the user's real values instead of the
    // neutral QML defaults. The blob is opaque to Rust; the launcher only has
    // to carry it verbatim, clear it on an empty string, and refuse anything
    // that would corrupt the line-oriented preferences file.
    let baseline = UiPreferences::default();
    assert!(
        baseline.service_backed_mirror_json.is_empty(),
        "a fresh install must start with nothing mirrored"
    );
    let mirror =
        r#"{"route-policy":{"doh-lockdown-enabled":true},"stability":{"fake-ip-enabled":true}}"#;
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert("serviceBackedMirrorJson".into(), serde_json::json!(mirror));
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("service-backed mirror payload must parse");
    assert_eq!(
        updated.service_backed_mirror_json, mirror,
        "a valid mirror blob must round-trip through the launcher parse"
    );

    // Empty string clears the mirror (nothing known any more).
    let mut cleared_object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    cleared_object.insert("serviceBackedMirrorJson".into(), serde_json::json!(""));
    let cleared = apply_qt_preferences_payload(
        &updated,
        &serde_json::Value::Object(cleared_object).to_string(),
    )
    .expect("clear payload must parse");
    assert!(
        cleared.service_backed_mirror_json.is_empty(),
        "an empty blob must clear the stored mirror"
    );

    // A multi-line value would split into bogus extra lines on the next read,
    // and an oversized one could balloon the preferences file — both reset to
    // empty instead of being stored.
    for rejected_value in [
        "{\"stability\":{\n\"fake-ip-enabled\":true}}".to_string(),
        format!("{{{}}}", "x".repeat(9000)),
    ] {
        let mut bad: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
        bad.insert(
            "serviceBackedMirrorJson".into(),
            serde_json::json!(rejected_value),
        );
        let guarded =
            apply_qt_preferences_payload(&updated, &serde_json::Value::Object(bad).to_string())
                .expect("payload with a malformed mirror must still parse");
        assert!(
            guarded.service_backed_mirror_json.is_empty(),
            "a multi-line or oversized mirror must be rejected rather than stored"
        );
    }
}

#[test]
fn service_intent_round_trips_through_payload() {
    // The user's intent for the service-owned settings is what the GUI replays
    // on connect, so losing it in the payload round-trip is exactly the bug it
    // exists to prevent: a service whose state DB was wiped answers with its
    // own defaults and the user's choices evaporate. Same opaque carry as the
    // mirror, and the same refusal to store anything that would corrupt the
    // line-oriented preferences file.
    let baseline = UiPreferences::default();
    assert!(
        baseline.service_intent_json.is_empty(),
        "a fresh install must start with no recorded intent"
    );
    let intent = r#"{"stability":{"verbose-logging":true,"fake-ip-enabled":true}}"#;
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert("serviceIntentJson".into(), serde_json::json!(intent));
    let updated =
        apply_qt_preferences_payload(&baseline, &serde_json::Value::Object(object).to_string())
            .expect("service intent payload must parse");
    assert_eq!(
        updated.service_intent_json, intent,
        "a valid intent blob must round-trip through the launcher parse"
    );

    // Empty string clears the intent ("reset to whatever the service says").
    let mut cleared_object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    cleared_object.insert("serviceIntentJson".into(), serde_json::json!(""));
    let cleared = apply_qt_preferences_payload(
        &updated,
        &serde_json::Value::Object(cleared_object).to_string(),
    )
    .expect("clear payload must parse");
    assert!(
        cleared.service_intent_json.is_empty(),
        "an empty blob must clear the recorded intent"
    );

    for rejected_value in [
        "{\"stability\":{\n\"verbose-logging\":true}}".to_string(),
        format!("{{{}}}", "x".repeat(9000)),
    ] {
        let mut bad: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
        bad.insert(
            "serviceIntentJson".into(),
            serde_json::json!(rejected_value),
        );
        let guarded =
            apply_qt_preferences_payload(&updated, &serde_json::Value::Object(bad).to_string())
                .expect("payload with a malformed intent must still parse");
        assert!(
            guarded.service_intent_json.is_empty(),
            "a multi-line or oversized intent must be rejected rather than stored"
        );
    }
}

#[test]
fn show_remembered_adapters_round_trips_through_payload() {
    // The "remembered but currently absent" ghost-row display toggle is a
    // device-local UI preference. It defaults ON (true); emit `false` and
    // confirm it round-trips, proving the launcher parses the key rather than
    // silently reading the default.
    let baseline = UiPreferences::default();
    assert!(
        baseline.show_remembered_adapters,
        "default must be ON so the ghost rows answer 'did it remember my VPN?'"
    );
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert("showRememberedAdapters".into(), false.into());
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("show-remembered-adapters payload must parse");
    assert!(
        !updated.show_remembered_adapters,
        "show-remembered-adapters toggle must round-trip"
    );
}

#[test]
fn unenforced_apps_ack_signature_round_trips_through_payload() {
    // The "app rules aren't active yet" dismiss signature must persist
    // across GUI restarts. Guard both directions AND
    // the omitted-key case (older QML payload must keep the stored value,
    // not blank it — the field is Option-mapped in ui_surface).
    let baseline = UiPreferences::default();
    assert!(baseline.unenforced_apps_ack_signature.is_empty());
    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert(
        "unenforcedAppsAckSig".into(),
        serde_json::json!("2gis.exe|vk.exe"),
    );
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("ack-signature payload must parse");
    assert_eq!(
        updated.unenforced_apps_ack_signature, "2gis.exe|vk.exe",
        "dismiss signature must round-trip through the launcher parse"
    );

    // Key omitted → stored value survives (older QML build compatibility).
    let kept = apply_qt_preferences_payload(&updated, &payload_with_theme("dark", false))
        .expect("payload without the key must parse");
    assert_eq!(
        kept.unenforced_apps_ack_signature, "2gis.exe|vk.exe",
        "a payload omitting the key must not blank the stored signature"
    );
}

#[test]
fn diagnostics_archive_options_round_trip_through_payload() {
    // The support-archive detail level and the "current session only" scope are
    // device-local export options the user re-picks on every hand-off if they
    // do not persist. Guard the happy path, the allow-list gate (an unknown
    // tier must not overwrite the stored one), and the omitted-key case.
    let baseline = UiPreferences::default();
    assert_eq!(
        baseline.diagnostics_archive_redaction_level, "standard",
        "the redacted tier must stay the default a user shares by accident"
    );
    assert!(
        baseline.diagnostics_archive_session_only,
        "the narrow session-only scope must stay the default"
    );

    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert(
        "diagnosticsArchiveRedactionLevel".into(),
        serde_json::json!("diagnostics"),
    );
    object.insert("diagnosticsArchiveSessionOnly".into(), false.into());
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("diagnostics-archive payload must parse");
    assert_eq!(
        updated.diagnostics_archive_redaction_level, "diagnostics",
        "the archive detail level must round-trip through the launcher parse"
    );
    assert!(
        !updated.diagnostics_archive_session_only,
        "the session-only scope must round-trip through the launcher parse"
    );

    // Unknown tier → the stored value survives (the store owns the allow-list).
    let mut bogus: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    bogus.insert(
        "diagnosticsArchiveRedactionLevel".into(),
        serde_json::json!("everything-unredacted"),
    );
    let rejected =
        apply_qt_preferences_payload(&updated, &serde_json::Value::Object(bogus).to_string())
            .expect("payload with an unknown tier must still parse");
    assert_eq!(
        rejected.diagnostics_archive_redaction_level, "diagnostics",
        "an unknown tier must be rejected rather than stored"
    );

    // Key omitted → the detail level survives; the scope flag falls back to its
    // `true` default rather than silently widening the archive.
    let kept = apply_qt_preferences_payload(&updated, &payload_with_theme("dark", false))
        .expect("payload without the keys must parse");
    assert_eq!(
        kept.diagnostics_archive_redaction_level, "diagnostics",
        "a payload omitting the key must not reset the stored detail level"
    );
    assert!(
        kept.diagnostics_archive_session_only,
        "an omitted scope key must resolve to the narrow default"
    );
}

#[test]
fn user_presets_dir_round_trips_through_payload() {
    // The folder the user points the quick-load dropdown at is a
    // device-local preference. Guard the happy path, the "explicit empty resets
    // to the shipped sets" path, and the omitted-key case (an older QML payload
    // must keep the configured folder rather than silently blanking it).
    let baseline = UiPreferences::default();
    assert!(
        baseline.user_presets_dir.is_empty(),
        "a fresh install must keep listing the shipped rule sets"
    );

    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert(
        "userPresetsDir".into(),
        serde_json::json!(r"D:\My Rule Sets"),
    );
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("user-presets-dir payload must parse");
    assert_eq!(
        updated.user_presets_dir, r"D:\My Rule Sets",
        "the chosen rule-set folder must round-trip through the launcher parse"
    );

    // Key omitted (older QML build) → the configured folder survives.
    let kept = apply_qt_preferences_payload(&updated, &payload_with_theme("dark", false))
        .expect("payload without the key must parse");
    assert_eq!(
        kept.user_presets_dir, r"D:\My Rule Sets",
        "a payload omitting the key must not blank the configured folder"
    );

    // Explicit empty string → back to the sets shipped with the app.
    let mut cleared_object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    cleared_object.insert("userPresetsDir".into(), serde_json::json!(""));
    let cleared = apply_qt_preferences_payload(
        &updated,
        &serde_json::Value::Object(cleared_object).to_string(),
    )
    .expect("clear payload must parse");
    assert!(
        cleared.user_presets_dir.is_empty(),
        "an empty value must reset the dropdown to the shipped rule sets"
    );

    // A multi-line value would split into bogus extra lines on the next read of
    // the line-oriented preferences file — keep the stored folder instead.
    let mut bad: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    bad.insert(
        "userPresetsDir".into(),
        serde_json::json!("D:\\Sets\nrules_primary.txt=oops"),
    );
    let guarded =
        apply_qt_preferences_payload(&updated, &serde_json::Value::Object(bad).to_string())
            .expect("payload with a malformed path must still parse");
    assert_eq!(
        guarded.user_presets_dir, r"D:\My Rule Sets",
        "a multi-line path must be rejected rather than stored"
    );
}

#[test]
fn selected_preset_set_round_trips_through_payload() {
    // The set the quick-load dropdown is left on must survive the GUI → launcher
    // round trip, or it would be re-derived on every launch — which is exactly
    // the "my choice keeps resetting" behaviour this replaces. Same three-way
    // contract as the folder above: happy path, omitted key, explicit clear.
    let baseline = UiPreferences::default();
    assert!(
        baseline.selected_preset_set.is_empty(),
        "a fresh install has no remembered rule-set choice"
    );

    let mut object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    object.insert(
        "selectedPresetSet".into(),
        serde_json::json!("user:My corporate set"),
    );
    let payload = serde_json::Value::Object(object).to_string();
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("selected-preset-set payload must parse");
    assert_eq!(
        updated.selected_preset_set, "user:My corporate set",
        "the picked rule set must round-trip through the launcher parse"
    );

    // Key omitted (older QML build) → the remembered choice survives.
    let kept = apply_qt_preferences_payload(&updated, &payload_with_theme("dark", false))
        .expect("payload without the key must parse");
    assert_eq!(
        kept.selected_preset_set, "user:My corporate set",
        "a payload omitting the key must not forget the user's pick"
    );

    // Explicit empty string → back to the default pick.
    let mut cleared_object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    cleared_object.insert("selectedPresetSet".into(), serde_json::json!(""));
    let cleared = apply_qt_preferences_payload(
        &updated,
        &serde_json::Value::Object(cleared_object).to_string(),
    )
    .expect("clear payload must parse");
    assert!(
        cleared.selected_preset_set.is_empty(),
        "an empty value must drop the remembered choice"
    );

    // A multi-line value would split the line-oriented preferences file.
    let mut bad: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&payload_with_theme("dark", false)).expect("base payload parses");
    bad.insert(
        "selectedPresetSet".into(),
        serde_json::json!("user:set\nuser_presets_dir=oops"),
    );
    let guarded =
        apply_qt_preferences_payload(&updated, &serde_json::Value::Object(bad).to_string())
            .expect("payload with a malformed selection must still parse");
    assert_eq!(
        guarded.selected_preset_set, "user:My corporate set",
        "a multi-line selection must be rejected rather than stored"
    );
}

#[test]
fn unknown_theme_string_falls_back_to_baseline() {
    let baseline = UiPreferences {
        theme_mode: ThemeMode::Dark,
        ..Default::default()
    };
    let payload = payload_with_theme("totally-not-a-theme", false);
    let updated = apply_qt_preferences_payload(&baseline, &payload)
        .expect("payload with unknown theme string must still parse");
    // Unknown theme falls back to the in-memory baseline.
    assert_eq!(updated.theme_mode, ThemeMode::Dark);
}

/// A surface that never emitted a payload must not write the preferences file.
///
/// Both user-facing binaries run the same launcher against the SAME file, each
/// from the snapshot it loaded at its own start, and the tray never emits. A
/// tray closing after the main window therefore used to rewrite the file from a
/// pre-session snapshot, silently discarding what the window had recorded —
/// including `service_intent_json`, the only place the user's decision about a
/// service-owned setting lives before the service accepts it.
#[test]
fn a_surface_that_emitted_nothing_does_not_rewrite_the_store() {
    let stale = UiPreferences {
        service_intent_json: "{\"stability\":{}}".to_string(),
        ..Default::default()
    };
    assert!(
        nrr_launcher::preferences_to_persist(stale, None).is_none(),
        "no payload means nothing was learned; writing the load-time snapshot back \
         clobbers whatever the other surface recorded during the session"
    );
}

/// The emitting surface still persists, payload applied over its own baseline.
#[test]
fn a_surface_that_emitted_a_payload_persists_it() {
    let baseline = UiPreferences {
        theme_mode: ThemeMode::System,
        ..Default::default()
    };
    let persisted =
        nrr_launcher::preferences_to_persist(baseline, Some(payload_with_theme("dark", false)))
            .expect("an emitted payload must be persisted");
    assert_eq!(persisted.theme_mode, ThemeMode::Dark);
}

/// An unusable payload keeps the baseline rather than dropping the write: the
/// surface did emit, so it is a participant in this session's file.
#[test]
fn an_unparsable_payload_falls_back_to_the_baseline() {
    let baseline = UiPreferences {
        theme_mode: ThemeMode::Dark,
        ..Default::default()
    };
    let persisted = nrr_launcher::preferences_to_persist(baseline, Some("not-json".to_string()))
        .expect("an emitted payload must still produce a write");
    assert_eq!(persisted.theme_mode, ThemeMode::Dark);
}
