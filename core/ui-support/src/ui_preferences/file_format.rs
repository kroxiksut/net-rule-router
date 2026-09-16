//! The on-disk format: parse one way, format the other, field by field.
//!
//! Both directions are written out by hand rather than derived, because the
//! file outlives the build that wrote it — an unknown key is kept, a malformed
//! value falls back, and neither is allowed to fail the whole read.

use super::*;

pub(super) fn parse_preferences(content: &str) -> UiPreferences {
    let mut preferences = UiPreferences::default();
    let newer_schema =
        declared_schema_version(content).filter(|v| *v > CURRENT_UI_PREFS_SCHEMA_VERSION);
    preferences.forward_compat.newer_schema_version = newer_schema;
    // The defaults were built from the SYSTEM language, which is not the one
    // the user picked. Whether the file carried its own values decides whether
    // they get recomputed below.
    let mut language_seen = false;
    let mut labels_seen = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();

        match key {
            "schema_version" => {
                // Read ahead of the loop, and re-stamped on save.
            }
            "launch_window_on_startup" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.launch_window_on_startup = parsed;
                }
            }
            "minimize_to_tray_instead_of_close" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.minimize_to_tray_instead_of_close = parsed;
                }
            }
            "show_notifications" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_notifications = parsed;
                }
            }
            "notify_suggestion_changes" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_suggestion_changes = parsed;
                }
            }
            "notify_block_notices" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_block_notices = parsed;
                }
            }
            "notify_rule_duplicates" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.notify_rule_duplicates = parsed;
                }
            }
            "hide_block_notice_addresses" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.hide_block_notice_addresses = parsed;
                }
            }
            "tray_notice_opacity_percent" => {
                if let Some(parsed) = parse_tray_notice_opacity_percent(value) {
                    preferences.tray_notice_opacity_percent = parsed;
                }
            }
            "reopen_last_section_on_startup" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.reopen_last_section_on_startup = parsed;
                }
            }
            "first_run_completed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.first_run_completed = parsed;
                }
            }
            "accepted_eula_version" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.accepted_eula_version = parsed;
                }
            }
            "theme_mode" => {
                if let Ok(parsed) = value.parse::<ThemeMode>() {
                    preferences.theme_mode = parsed;
                }
            }
            "accessibility_high_contrast" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_high_contrast = parsed;
                }
            }
            "accessibility_ui_font_scale_percent" => {
                if let Some(parsed) = parse_font_scale_percent(value) {
                    preferences.accessibility_ui_font_scale_percent = parsed;
                }
            }
            "accessibility_system_font" => {
                if let Ok(parsed) = value.parse::<SystemFontFamily>() {
                    preferences.accessibility_system_font = parsed;
                }
            }
            "accessibility_enhanced_focus_indicator" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_enhanced_focus_indicator = parsed;
                }
            }
            "accessibility_simplified_labels" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.accessibility_simplified_labels = parsed;
                }
            }
            "tooltips_enabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.tooltips_enabled = parsed;
                }
            }
            // Resolved against the catalog, not just canonicalised: a tag no
            // catalog carries (`zz`, a typo) left every `tr()` on its English
            // fallback, which reads as "the app forgot my language".
            "language" => {
                if let Some(parsed) = parse_language_hint(value) {
                    preferences.language = parsed;
                    language_seen = true;
                }
            }
            "last_opened_section" => {
                if let Ok(parsed) = value.parse::<AppSection>() {
                    preferences.last_opened_section = parsed;
                }
            }
            "route_primary_label" => {
                if !value.is_empty() {
                    preferences.route_primary_label = value.to_string();
                    labels_seen = true;
                }
            }
            "route_secondary_label" => {
                if !value.is_empty() {
                    preferences.route_secondary_label = value.to_string();
                    labels_seen = true;
                }
            }
            "show_bluetooth_adapters" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_bluetooth_adapters = parsed;
                }
            }
            "show_audit_tab" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_audit_tab = parsed;
                }
            }
            "admin_auto_revoke_disabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.admin_auto_revoke_disabled = parsed;
                }
            }
            // Clamped, not reverted: an out-of-range value is a user who wanted
            // the extreme, and silently substituting the default moves a
            // security-relevant timer to a number nobody asked for. Garbage
            // (unparseable) keeps the current value, like every other number here.
            "admin_auto_revoke_minutes" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.admin_auto_revoke_minutes =
                        parsed.clamp(ADMIN_AUTO_REVOKE_MIN_MINUTES, ADMIN_AUTO_REVOKE_MAX_MINUTES);
                }
            }
            "settings_autosave_secs" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.settings_autosave_secs =
                        parsed.clamp(SETTINGS_AUTOSAVE_MIN_SECS, SETTINGS_AUTOSAVE_MAX_SECS);
                }
            }
            "allow_mode_a_killswitch" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.allow_mode_a_killswitch = parsed;
                }
            }
            "routing_detailed_mode" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.routing_detailed_mode = parsed;
                }
            }
            "show_remembered_adapters" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_remembered_adapters = parsed;
                }
            }
            "auto_confirm_adapter_id_change" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.auto_confirm_adapter_id_change = parsed;
                }
            }
            // Block-all banner opt-out. Missing key resolves to the ON
            // default via `defaults()`.
            "warn_kill_switch_block_all" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.warn_kill_switch_block_all = parsed;
                }
            }
            // Persisted acknowledgement of the block-all banner. Missing key
            // (pre-existing file) resolves to the `false` default via `defaults()`.
            "kill_switch_banner_acknowledged" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.kill_switch_banner_acknowledged = parsed;
                }
            }
            // Persisted acknowledgement of the "additional adapter not found"
            // banner. Missing key (pre-existing file) resolves to the `false`
            // default via `defaults()`.
            "missing_secondary_banner_acknowledged" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.missing_secondary_banner_acknowledged = parsed;
                }
            }
            // Selected traffic-statistics period slug. Non-empty gate so a
            // missing key keeps the `"today"` default; the GUI normalizes any
            // unexpected slug back to `"today"`.
            "traffic_stats_period" => {
                if !value.is_empty() {
                    preferences.traffic_stats_period = value.to_string();
                }
            }
            // Remembered CSV export unit. Only a known slug is accepted, so a
            // hand-edited or older file cannot leave the panel on a unit the
            // exporter does not implement.
            "traffic_export_unit" => {
                if TRAFFIC_EXPORT_UNITS.contains(&value) {
                    preferences.traffic_export_unit = value.to_string();
                }
            }
            // Remembered support-archive privacy tier. Only a known slug is
            // accepted, so a hand-edited or older file cannot leave the export
            // pointing at a tier the archive writer does not implement.
            "diagnostics_archive_redaction_level" => {
                if DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS.contains(&value) {
                    preferences.diagnostics_archive_redaction_level = value.to_string();
                }
            }
            // Remembered "current session only" archive scope. Missing key
            // (pre-existing file) resolves to the `true` default.
            "diagnostics_archive_session_only" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.diagnostics_archive_session_only = parsed;
                }
            }
            // Raw-log attachment cap in MiB; `0` = unlimited. A missing key
            // (pre-existing file) resolves to the unlimited default, and an
            // unparsable value keeps whatever is already there rather than
            // silently capping an export the user expected to be complete.
            "archive_log_budget_mib" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.archive_log_budget_mib = parsed;
                }
            }
            // Persisted notification-dismiss signature. Free-form single-line
            // value (sorted exe patterns joined with `|`); empty is a valid
            // "never dismissed" state, so no non-empty gate.
            "unenforced_apps_ack_signature" => {
                preferences.unenforced_apps_ack_signature = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.unenforced_apps_ack_signature),
                );
            }
            // Overlap pairs the user asked to keep. Free-form single-line
            // value; empty is the valid "nothing kept" state.
            "rules_overlap_keep_signature" => {
                preferences.rules_overlap_keep_signature = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.rules_overlap_keep_signature),
                );
            }
            // Confirmed VPN executable path. Free-form single-line value;
            // empty is the valid "not set" state, so no non-empty gate.
            "confirmed_vpn_exe_path" => {
                preferences.confirmed_vpn_exe_path = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.confirmed_vpn_exe_path),
                );
            }
            // Semicolon-joined list of confirmed VPN executables. Free-form
            // single-line value; empty is the valid "none" state, so no
            // non-empty gate.
            "confirmed_vpn_exe_paths" => {
                preferences.confirmed_vpn_exe_paths = storable_line_or(
                    key,
                    value.to_string(),
                    std::mem::take(&mut preferences.confirmed_vpn_exe_paths),
                );
            }
            "selected_primary_interface_name" => {
                preferences.selected_primary_interface_name = value.to_string();
            }
            "selected_primary_interface_id" => {
                preferences.selected_primary_interface_id = value.to_string();
            }
            "primary_role_user_confirmed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.primary_role_user_confirmed = parsed;
                }
            }
            "selected_secondary_interface_name" => {
                preferences.selected_secondary_interface_name = value.to_string();
            }
            "selected_secondary_interface_id" => {
                preferences.selected_secondary_interface_id = value.to_string();
            }
            "secondary_role_user_confirmed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.secondary_role_user_confirmed = parsed;
                }
            }
            "route_behavior_mode" => {
                if let Ok(parsed) = value.parse::<RouteBehaviorMode>() {
                    preferences.route_behavior_mode = parsed;
                }
            }
            "rules_view_sort" => {
                if let Ok(parsed) = value.parse::<RulesViewSort>() {
                    preferences.rules_view_sort = parsed;
                }
            }
            "rules_file_change_behavior" => {
                if let Ok(parsed) = value.parse::<RulesFileChangeBehavior>() {
                    preferences.rules_file_change_behavior = parsed;
                }
            }
            // File-source state. Empty value parses as `None` (the sentinel
            // for "not yet recorded"); any non-empty string parses as
            // `Some`.
            "last_saved_path_primary" => {
                preferences.last_saved_path_primary = parse_optional_string(value);
            }
            "last_saved_path_secondary" => {
                preferences.last_saved_path_secondary = parse_optional_string(value);
            }
            // Display-only source paths (may point inside the bundled tree).
            "last_loaded_path_primary" => {
                preferences.last_loaded_path_primary = parse_optional_string(value);
            }
            "last_loaded_path_secondary" => {
                preferences.last_loaded_path_secondary = parse_optional_string(value);
            }
            "auto_open_on_launch_path_primary" => {
                preferences.auto_open_on_launch_path_primary = parse_optional_string(value);
            }
            "auto_open_on_launch_path_secondary" => {
                preferences.auto_open_on_launch_path_secondary = parse_optional_string(value);
            }
            "last_file_synced_revision_id_primary" => {
                preferences.last_file_synced_revision_id_primary = parse_optional_string(value);
            }
            "last_file_synced_revision_id_secondary" => {
                preferences.last_file_synced_revision_id_secondary = parse_optional_string(value);
            }
            "last_file_synced_hash_primary" => {
                preferences.last_file_synced_hash_primary = parse_optional_string(value);
            }
            "last_file_synced_hash_secondary" => {
                preferences.last_file_synced_hash_secondary = parse_optional_string(value);
            }
            "service_install_uac_declined_at_epoch" => {
                preferences.service_install_uac_declined_at_epoch = parse_optional_i64(value);
            }
            "service_install_uac_declined_count" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.service_install_uac_declined_count = parsed;
                }
            }
            "service_install_prompt_suppressed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.service_install_prompt_suppressed = parsed;
                }
            }
            "auto_load_rules_on_launch" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.auto_load_rules_on_launch = parsed;
                }
            }
            "export_include_comments" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.export_include_comments = parsed;
                }
            }
            "import_only_active" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.import_only_active = parsed;
                }
            }
            "compat_banner_mode" => {
                preferences.compat_banner_mode =
                    allowed_slug_or(value, &COMPAT_BANNER_MODES, &preferences.compat_banner_mode);
            }
            "update_page_url" => {
                preferences.update_page_url = value.to_string();
            }
            "show_bundled_presets" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.show_bundled_presets = parsed;
                }
            }
            // User-owned rule-set folder for the quick-load dropdown.
            // Free-form single-line path; empty is the valid "use the sets
            // shipped with the app" state, so no non-empty gate.
            "user_presets_dir" => {
                preferences.user_presets_dir = value.to_string();
            }
            // The remembered quick-load selection, `<source>:<label>`. Kept
            // free-form: the label is a folder name the user controls, and the
            // GUI already ignores a value whose set is gone.
            "selected_preset_set" => {
                preferences.selected_preset_set = value.to_string();
            }
            // Persisted per-adapter VPN-split banner ack. Free-form adapter
            // display name; empty = never acknowledged.
            "secondary_split_ack_adapter_name" => {
                preferences.secondary_split_ack_adapter_name = value.to_string();
            }
            "merge_conflict_policy" => {
                preferences.merge_conflict_policy = allowed_slug_or(
                    value,
                    &MERGE_CONFLICT_POLICIES,
                    &preferences.merge_conflict_policy,
                );
            }
            // Device-local mirrors of per-SID policy toggles. Missing keys
            // fall through to the struct defaults.
            "route_include_subdomains" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_include_subdomains = parsed;
                }
            }
            "route_shared_ip_policy" => {
                if !value.is_empty() {
                    preferences.route_shared_ip_policy = value.to_string();
                }
            }
            "route_kill_switch_block_all" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_block_all = parsed;
                }
            }
            "route_kill_switch_fail_closed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_fail_closed = parsed;
                }
            }
            "route_kill_switch_protocols" => {
                // Masking a nonsense value invents a meaning for it: `128 &
                // 0x7F` is 0, and an empty protocol mask makes the codegen emit
                // no filter at all — the kill switch reads as ON and blocks
                // nothing. A value outside the mask, or one that selects
                // nothing, is not a preference; it is a damaged line, and the
                // default (every protocol) is the safe reading.
                if let Ok(parsed) = value.parse::<u32>() {
                    if parsed != 0 && parsed & !0x7F == 0 {
                        preferences.route_kill_switch_protocols = parsed;
                    }
                }
            }
            "route_kill_switch_enabled" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_kill_switch_enabled = parsed;
                }
            }
            "route_allow_dns_over_primary" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_allow_dns_over_primary = parsed;
                }
            }
            "route_mode_a_coverage_strategy" => {
                if matches!(value, "per-ip" | "fail-closed-unknown" | "zone-widening") {
                    preferences.route_mode_a_coverage_strategy = value.to_string();
                }
            }
            "route_resolve_hosts_bypass" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.route_resolve_hosts_bypass = parsed;
                }
            }
            "route_enforcement_mode" => {
                if matches!(value, "reactive" | "resolver") {
                    preferences.route_enforcement_mode = value.to_string();
                }
            }
            "route_liveness_window_secs" => {
                if let Ok(parsed) = value.parse::<u32>() {
                    preferences.route_liveness_window_secs = clamp_liveness_window_secs(parsed);
                }
            }
            "route_pending_offline_json" => {
                preferences.route_pending_offline_json =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            "allow_saving_into_bundled_presets" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.allow_saving_into_bundled_presets = parsed;
                }
            }
            "rules_folder_suggestion_dismissed" => {
                if let Some(parsed) = parse_bool(value) {
                    preferences.rules_folder_suggestion_dismissed = parsed;
                }
            }
            "cache_table_column_widths" => {
                preferences.cache_table_column_widths =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // Last-known service-owned values, mirrored for display while the
            // service is stopped. Same opaque single-line-object gate as the
            // two blobs above.
            "service_backed_mirror_json" => {
                preferences.service_backed_mirror_json =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // What the user decided the service-owned settings should be.
            // Same opaque single-line-object gate as the mirror above.
            "service_intent_json" => {
                preferences.service_intent_json =
                    storable_json_blob_or_empty(key, value.to_string());
            }
            // A key this build has none for. From a NEWER file it is a setting
            // the user made in a build that has one, so it is kept verbatim and
            // written back; from a file of our own version it is the residue of
            // a key we removed, and dropping it is how the file shrinks.
            _ => {
                if newer_schema.is_some() {
                    preferences
                        .forward_compat
                        .unknown_lines
                        .push(line.to_string());
                }
            }
        }
    }

    // A file that named a language but no labels was written before the labels
    // existed; deriving them from the system language then hands a Russian-UI
    // user "Primary"/"Secondary".
    if language_seen && !labels_seen {
        let (primary, secondary) = default_route_labels(&preferences.language);
        preferences.route_primary_label = primary;
        preferences.route_secondary_label = secondary;
    }

    normalize_theme_preferences(&mut preferences);
    preferences
}

/// Structural sanity gate for the opaque pending-offline JSON blob
/// (ui-support deliberately has no JSON dependency; the QML
/// side owns the schema). Accepts an empty string (= none) or a single-line
/// `{…}` object up to [`MAX_STORED_JSON_BLOB_BYTES`] — plenty for every routing
/// field with headroom, small enough that a corrupted preferences file cannot
/// balloon memory. Public because the QML payload path applies the SAME gate on
/// the way in: five hand-copied versions of it lived here and in `ui_surface`,
/// and one threshold drifting apart from the rest loses a blob silently.
/// Rejects any embedded newline (L3 review-fix): the value lives on ONE
/// `key=value` line, so a `\n`/`\r` would split it into bogus extra lines on
/// the next read — reject rather than corrupt the line-oriented file.
pub fn is_storable_json_blob(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= MAX_STORED_JSON_BLOB_BYTES
            && value.starts_with('{')
            && value.ends_with('}')
            && !value.contains(['\n', '\r']))
}

/// A blob that passes [`is_storable_json_blob`], or `""` plus a diagnostic.
///
/// Both sides of the round-trip reduce a rejected blob to "none", and both used
/// to do it silently — so `service_intent_json`, the only record of what the
/// user decided, could evaporate in exactly the way the field exists to
/// prevent. `field` names the key so the line is actionable.
pub fn storable_json_blob_or_empty(field: &str, value: String) -> String {
    if is_storable_json_blob(&value) {
        return value;
    }
    eprintln!(
        "nrr: dropping {field} ({} bytes): not a single-line JSON object within \
         {MAX_STORED_JSON_BLOB_BYTES} bytes",
        value.len()
    );
    String::new()
}

fn normalize_theme_preferences(preferences: &mut UiPreferences) {
    // Backward compatibility: legacy persisted flag may still be true even when
    // theme_mode was stored before high-contrast became a dedicated mode.
    if preferences.accessibility_high_contrast && preferences.theme_mode != ThemeMode::HighContrast
    {
        preferences.theme_mode = ThemeMode::HighContrast;
    }

    // Keep compatibility flag as a derived mirror of selected mode.
    preferences.accessibility_high_contrast = preferences.theme_mode == ThemeMode::HighContrast;
}

/// Renders one preference value so it cannot become two lines.
///
/// The file is `key=value` per line and the parser splits on the first `=`, so
/// a value carrying a newline used to write a SECOND, forged pair — a label of
/// `Main` plus a newline plus `first_run_completed=false` restarted the setup
/// wizard on the next launch. The reader rejected such values on some paths;
/// the writer accepted every one of them. A preset directory whose name
/// contains a newline is perfectly legal on Linux, so this is not hypothetical.
///
/// Control characters are replaced rather than dropped: what the user typed
/// stays recognisable, and the file stays parseable.
fn one_line(value: &impl std::fmt::Display) -> String {
    let rendered = value.to_string();
    if rendered.contains(['\r', '\n']) {
        rendered.replace(['\r', '\n'], " ")
    } else {
        rendered
    }
}

pub(super) fn format_preferences(preferences: &UiPreferences) -> String {
    let mut rendered = format!(
        concat!(
            "# NetRuleRouter managed UI preferences\n",
            "schema_version={}\n",
            "launch_window_on_startup={}\n",
            "minimize_to_tray_instead_of_close={}\n",
            "show_notifications={}\n",
            "notify_suggestion_changes={}\n",
            "reopen_last_section_on_startup={}\n",
            "first_run_completed={}\n",
            "accepted_eula_version={}\n",
            "theme_mode={}\n",
            "accessibility_high_contrast={}\n",
            "accessibility_ui_font_scale_percent={}\n",
            "accessibility_system_font={}\n",
            "accessibility_enhanced_focus_indicator={}\n",
            "accessibility_simplified_labels={}\n",
            "tooltips_enabled={}\n",
            "language={}\n",
            "route_primary_label={}\n",
            "route_secondary_label={}\n",
            "show_bluetooth_adapters={}\n",
            "show_audit_tab={}\n",
            "admin_auto_revoke_disabled={}\n",
            "admin_auto_revoke_minutes={}\n",
            "settings_autosave_secs={}\n",
            "allow_mode_a_killswitch={}\n",
            "routing_detailed_mode={}\n",
            "show_remembered_adapters={}\n",
            "selected_primary_interface_id={}\n",
            "selected_primary_interface_name={}\n",
            "primary_role_user_confirmed={}\n",
            "selected_secondary_interface_id={}\n",
            "selected_secondary_interface_name={}\n",
            "secondary_role_user_confirmed={}\n",
            "route_behavior_mode={}\n",
            "last_opened_section={}\n",
            "rules_view_sort={}\n",
            "rules_file_change_behavior={}\n",
            "last_saved_path_primary={}\n",
            "last_saved_path_secondary={}\n",
            "auto_open_on_launch_path_primary={}\n",
            "auto_open_on_launch_path_secondary={}\n",
            "last_file_synced_revision_id_primary={}\n",
            "last_file_synced_revision_id_secondary={}\n",
            "last_file_synced_hash_primary={}\n",
            "last_file_synced_hash_secondary={}\n",
            "service_install_uac_declined_at_epoch={}\n",
            "service_install_uac_declined_count={}\n",
            "service_install_prompt_suppressed={}\n",
            "auto_load_rules_on_launch={}\n",
            "export_include_comments={}\n",
            "import_only_active={}\n",
            "compat_banner_mode={}\n",
            "update_page_url={}\n",
            "show_bundled_presets={}\n",
            "user_presets_dir={}\n",
            "selected_preset_set={}\n",
            "merge_conflict_policy={}\n",
            "auto_confirm_adapter_id_change={}\n",
            "warn_kill_switch_block_all={}\n",
            "kill_switch_banner_acknowledged={}\n",
            "missing_secondary_banner_acknowledged={}\n",
            "traffic_stats_period={}\n",
            "traffic_export_unit={}\n",
            "diagnostics_archive_redaction_level={}\n",
            "diagnostics_archive_session_only={}\n",
            "archive_log_budget_mib={}\n",
            "secondary_split_ack_adapter_name={}\n",
            "route_include_subdomains={}\n",
            "route_shared_ip_policy={}\n",
            "route_kill_switch_block_all={}\n",
            "route_kill_switch_fail_closed={}\n",
            "route_kill_switch_protocols={}\n",
            "route_kill_switch_enabled={}\n",
            "route_allow_dns_over_primary={}\n",
            "route_mode_a_coverage_strategy={}\n",
            "route_resolve_hosts_bypass={}\n",
            "route_enforcement_mode={}\n",
            "route_liveness_window_secs={}\n",
            "route_pending_offline_json={}\n",
            "allow_saving_into_bundled_presets={}\n",
            "rules_folder_suggestion_dismissed={}\n",
            "cache_table_column_widths={}\n",
            "service_backed_mirror_json={}\n",
            "service_intent_json={}\n",
            "unenforced_apps_ack_signature={}\n",
            "rules_overlap_keep_signature={}\n",
            "confirmed_vpn_exe_path={}\n",
            "confirmed_vpn_exe_paths={}\n",
            "last_loaded_path_primary={}\n",
            "last_loaded_path_secondary={}\n",
            "notify_block_notices={}\n",
            "notify_rule_duplicates={}\n",
            "hide_block_notice_addresses={}\n",
            "tray_notice_opacity_percent={}\n"
        ),
        preferences.forward_compat.schema_stamp(),
        one_line(&preferences.launch_window_on_startup),
        one_line(&preferences.minimize_to_tray_instead_of_close),
        one_line(&preferences.show_notifications),
        one_line(&preferences.notify_suggestion_changes),
        one_line(&preferences.reopen_last_section_on_startup),
        one_line(&preferences.first_run_completed),
        one_line(&preferences.accepted_eula_version),
        one_line(&preferences.theme_mode),
        one_line(&preferences.accessibility_high_contrast),
        one_line(&preferences.accessibility_ui_font_scale_percent),
        one_line(&preferences.accessibility_system_font),
        one_line(&preferences.accessibility_enhanced_focus_indicator),
        one_line(&preferences.accessibility_simplified_labels),
        one_line(&preferences.tooltips_enabled),
        one_line(&preferences.language),
        one_line(&preferences.route_primary_label),
        one_line(&preferences.route_secondary_label),
        one_line(&preferences.show_bluetooth_adapters),
        one_line(&preferences.show_audit_tab),
        one_line(&preferences.admin_auto_revoke_disabled),
        one_line(&preferences.admin_auto_revoke_minutes),
        one_line(&preferences.settings_autosave_secs),
        one_line(&preferences.allow_mode_a_killswitch),
        one_line(&preferences.routing_detailed_mode),
        one_line(&preferences.show_remembered_adapters),
        one_line(&preferences.selected_primary_interface_id),
        one_line(&preferences.selected_primary_interface_name),
        one_line(&preferences.primary_role_user_confirmed),
        one_line(&preferences.selected_secondary_interface_id),
        one_line(&preferences.selected_secondary_interface_name),
        one_line(&preferences.secondary_role_user_confirmed),
        one_line(&preferences.route_behavior_mode),
        one_line(&preferences.last_opened_section),
        one_line(&preferences.rules_view_sort),
        one_line(&preferences.rules_file_change_behavior),
        optional_string_field(&preferences.last_saved_path_primary),
        optional_string_field(&preferences.last_saved_path_secondary),
        optional_string_field(&preferences.auto_open_on_launch_path_primary),
        optional_string_field(&preferences.auto_open_on_launch_path_secondary),
        optional_string_field(&preferences.last_file_synced_revision_id_primary),
        optional_string_field(&preferences.last_file_synced_revision_id_secondary),
        optional_string_field(&preferences.last_file_synced_hash_primary),
        optional_string_field(&preferences.last_file_synced_hash_secondary),
        optional_i64_field(preferences.service_install_uac_declined_at_epoch),
        one_line(&preferences.service_install_uac_declined_count),
        one_line(&preferences.service_install_prompt_suppressed),
        one_line(&preferences.auto_load_rules_on_launch),
        one_line(&preferences.export_include_comments),
        one_line(&preferences.import_only_active),
        one_line(&preferences.compat_banner_mode),
        one_line(&preferences.update_page_url),
        one_line(&preferences.show_bundled_presets),
        one_line(&preferences.user_presets_dir),
        one_line(&preferences.selected_preset_set),
        one_line(&preferences.merge_conflict_policy),
        one_line(&preferences.auto_confirm_adapter_id_change),
        one_line(&preferences.warn_kill_switch_block_all),
        one_line(&preferences.kill_switch_banner_acknowledged),
        one_line(&preferences.missing_secondary_banner_acknowledged),
        one_line(&preferences.traffic_stats_period),
        one_line(&preferences.traffic_export_unit),
        one_line(&preferences.diagnostics_archive_redaction_level),
        one_line(&preferences.diagnostics_archive_session_only),
        one_line(&preferences.archive_log_budget_mib),
        one_line(&preferences.secondary_split_ack_adapter_name),
        one_line(&preferences.route_include_subdomains),
        one_line(&preferences.route_shared_ip_policy),
        one_line(&preferences.route_kill_switch_block_all),
        one_line(&preferences.route_kill_switch_fail_closed),
        one_line(&preferences.route_kill_switch_protocols),
        one_line(&preferences.route_kill_switch_enabled),
        one_line(&preferences.route_allow_dns_over_primary),
        one_line(&preferences.route_mode_a_coverage_strategy),
        one_line(&preferences.route_resolve_hosts_bypass),
        one_line(&preferences.route_enforcement_mode),
        one_line(&preferences.route_liveness_window_secs),
        one_line(&preferences.route_pending_offline_json),
        one_line(&preferences.allow_saving_into_bundled_presets),
        one_line(&preferences.rules_folder_suggestion_dismissed),
        one_line(&preferences.cache_table_column_widths),
        one_line(&preferences.service_backed_mirror_json),
        one_line(&preferences.service_intent_json),
        one_line(&preferences.unenforced_apps_ack_signature),
        one_line(&preferences.rules_overlap_keep_signature),
        one_line(&preferences.confirmed_vpn_exe_path),
        one_line(&preferences.confirmed_vpn_exe_paths),
        optional_string_field(&preferences.last_loaded_path_primary),
        optional_string_field(&preferences.last_loaded_path_secondary),
        one_line(&preferences.notify_block_notices),
        one_line(&preferences.notify_rule_duplicates),
        one_line(&preferences.hide_block_notice_addresses),
        preferences.tray_notice_opacity_percent
    );

    for line in &preferences.forward_compat.unknown_lines {
        rendered.push_str(&one_line(line));
        rendered.push('\n');
    }
    rendered
}

/// Format an `Option<i64>` for the preferences file. `None` → empty
/// string; `Some(n)` → decimal. Matching parser is [`parse_optional_i64`].
fn optional_i64_field(value: Option<i64>) -> String {
    match value {
        None => String::new(),
        Some(n) => n.to_string(),
    }
}

/// Format an `Option<String>` for the preferences file. `None` → empty
/// string; `Some(s)` → trimmed value as-is. The matching parser
/// ([`parse_optional_string`]) treats empty as `None`.
fn optional_string_field(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("")
}

/// Parse an `Option<String>` from a preferences value. Empty string (and
/// pure whitespace) → `None`; otherwise the trimmed value wrapped in
/// `Some`. Mirrors the on-disk convention that absent = empty `key=`
/// line = "not recorded yet".
fn parse_optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse an `Option<i64>` from a preferences value. Empty string →
/// `None`; non-empty parsed via `str::parse::<i64>`. A malformed value
/// also yields `None` (silently — same lenient policy the rest of the
/// parser follows).
fn parse_optional_i64(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse::<i64>().ok()
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Clamped, not rejected. Rejecting made an out-of-range value load as the
/// DEFAULT, and the default is the maximum — so `20` ("nearly transparent")
/// came back as 100, fully opaque, the opposite of what was asked. The
/// write path clamps for exactly this reason; the read path now agrees.
fn parse_tray_notice_opacity_percent(value: &str) -> Option<u16> {
    let parsed = value.parse::<u16>().ok()?;
    Some(parsed.clamp(
        TRAY_NOTICE_OPACITY_MIN_PERCENT,
        TRAY_NOTICE_OPACITY_MAX_PERCENT,
    ))
}

fn parse_font_scale_percent(value: &str) -> Option<u16> {
    let parsed = value.parse::<u16>().ok()?;
    if (80..=300).contains(&parsed) {
        Some(parsed)
    } else {
        None
    }
}

/// Drop parked offline intents the user made more than
/// [`PARKED_INTENT_TTL_SECONDS`] ago.
///
/// Applied on load rather than on read: an intent nobody will act on should not
/// reach the GUI at all, and the next save writes the store out empty.
pub(super) fn without_expired_parked_intents(
    mut prefs: UiPreferences,
    now_ms: i64,
) -> UiPreferences {
    if nrr_shared::parked_intents_expired(&prefs.route_pending_offline_json, now_ms) {
        prefs.route_pending_offline_json.clear();
    }
    prefs
}

/// Current Unix epoch in milliseconds; `0` when the clock is before the epoch,
/// which only makes every park look fresh.
pub(super) fn unix_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}
