use super::*;

impl QtPreferencesPayload {
    // `apply_over` writes the adapter-binding fields back into
    // `UiPreferences`: the app's own store of what the service enforces per
    // SID, and what every panel shows while the service is stopped.
    pub(super) fn apply_over(self, mut current: UiPreferences) -> UiPreferences {
        // Absent means "not reported", never "set it to the type default".
        // These nineteen fields used to be mandatory, so one key missing from
        // the QML payload failed the whole parse — and the launcher then wrote
        // its start-up baseline back over the file. Making them defaultable
        // without making them optional would have been worse: a forgotten key
        // would silently reset the setting instead of failing loudly.
        if let Some(v) = self.launch_window_on_startup {
            current.launch_window_on_startup = v;
        }
        if let Some(v) = self.minimize_to_tray_instead_of_close {
            current.minimize_to_tray_instead_of_close = v;
        }
        if let Some(v) = self.show_notifications {
            current.show_notifications = v;
        }
        current.notify_suggestion_changes = self.notify_suggestion_changes;
        current.notify_block_notices = self.notify_block_notices;
        current.notify_rule_duplicates = self.notify_rule_duplicates;
        current.hide_block_notice_addresses = self.hide_block_notice_addresses;
        current.tray_notice_opacity_percent = self.tray_notice_opacity_percent.clamp(
            nrr_ui_support::ui_preferences::TRAY_NOTICE_OPACITY_MIN_PERCENT,
            nrr_ui_support::ui_preferences::TRAY_NOTICE_OPACITY_MAX_PERCENT,
        );
        if let Some(v) = self.reopen_last_section_on_startup {
            current.reopen_last_section_on_startup = v;
        }
        if let Some(v) = self.first_run_completed {
            current.first_run_completed = v;
        }
        current.accepted_eula_version = self.accepted_eula_version;

        if let Some(mode) = self.theme_mode.as_deref() {
            current.theme_mode = mode.parse::<ThemeMode>().unwrap_or(current.theme_mode);
        }
        if self.accessibility_high_contrast == Some(true) {
            current.theme_mode = ThemeMode::HighContrast;
        }
        current.accessibility_high_contrast = current.theme_mode == ThemeMode::HighContrast;
        if let Some(scale) = self.font_scale_percent {
            current.accessibility_ui_font_scale_percent = scale.clamp(80, 300);
        }
        if let Some(font) = self.system_font.as_deref() {
            current.accessibility_system_font = font
                .parse::<SystemFontFamily>()
                .unwrap_or(current.accessibility_system_font);
        }
        if let Some(v) = self.enhanced_focus {
            current.accessibility_enhanced_focus_indicator = v;
        }
        if let Some(v) = self.simplified_labels {
            current.accessibility_simplified_labels = v;
        }
        if let Some(v) = self.tooltips_enabled {
            current.tooltips_enabled = v;
        }
        if let Some(language_id) = self.language.as_deref().and_then(canonicalize_language_id) {
            current.language = language_id;
        }
        if let Some(label) = self.route_primary_label.filter(|l| !l.trim().is_empty()) {
            current.route_primary_label = label;
        }
        if let Some(label) = self.route_secondary_label.filter(|l| !l.trim().is_empty()) {
            current.route_secondary_label = label;
        }
        current.selected_primary_interface_id = self.selected_primary_interface_id;
        if let Some(name) = self.selected_primary_interface_name {
            current.selected_primary_interface_name = name;
        }
        current.primary_role_user_confirmed = self.primary_role_user_confirmed;
        current.selected_secondary_interface_id = self.selected_secondary_interface_id;
        if let Some(name) = self.selected_secondary_interface_name {
            current.selected_secondary_interface_name = name;
        }
        current.secondary_role_user_confirmed = self.secondary_role_user_confirmed;
        if let Some(mode) = self.route_behavior_mode.as_deref() {
            current.route_behavior_mode = mode
                .parse::<RouteBehaviorMode>()
                .unwrap_or(current.route_behavior_mode);
        }
        // Policy-toggle mirrors. An empty shared-IP slug means the QML
        // build did not emit it (older payload) — keep the current value
        // rather than blanking it.
        current.route_include_subdomains = self.route_include_subdomains;
        if !self.route_shared_ip_policy.is_empty() {
            current.route_shared_ip_policy = self.route_shared_ip_policy;
        }
        current.route_kill_switch_block_all = self.route_kill_switch_block_all;
        current.route_kill_switch_fail_closed = self.route_kill_switch_fail_closed;
        current.route_kill_switch_protocols = self.route_kill_switch_protocols & 0x7F;
        // Master kill-switch toggle + DNS-over-primary opt-in.
        current.route_kill_switch_enabled = self.route_kill_switch_enabled;
        current.route_allow_dns_over_primary = self.route_allow_dns_over_primary;
        // Mode-A coverage strategy + hosts-bypass. Unknown slug from a
        // divergent QML build is dropped (keeps the stored value).
        if matches!(
            self.route_mode_a_coverage_strategy.as_str(),
            "per-ip" | "fail-closed-unknown" | "zone-widening"
        ) {
            current.route_mode_a_coverage_strategy = self.route_mode_a_coverage_strategy;
        }
        current.route_resolve_hosts_bypass = self.route_resolve_hosts_bypass;
        if matches!(
            self.route_enforcement_mode.as_str(),
            "reactive" | "resolver"
        ) {
            current.route_enforcement_mode = self.route_enforcement_mode;
        }
        // Clamp the liveness window: `0` stays `0` (disabled), any
        // non-zero value is clamped to `[5, 3600]`.
        current.route_liveness_window_secs = if self.route_liveness_window_secs == 0 {
            0
        } else {
            self.route_liveness_window_secs.clamp(5, 3600)
        };
        // Unconditional carry (an EMPTY string means "pending set
        // applied/discarded" and must clear the stored value).
        current.route_pending_offline_json = storable_json_blob_or_empty(
            "route_pending_offline_json",
            self.route_pending_offline_json,
        );
        // Cache-viewer column widths — unconditional carry (empty clears to
        // defaults).
        current.cache_table_column_widths = storable_json_blob_or_empty(
            "cache_table_column_widths",
            self.cache_table_column_widths,
        );
        // Last-known service-owned values — unconditional carry (an EMPTY
        // string is the legitimate "nothing mirrored yet" state).
        current.service_backed_mirror_json = storable_json_blob_or_empty(
            "service_backed_mirror_json",
            self.service_backed_mirror_json,
        );
        // The user's intent for those same settings. A blob failing the gate
        // resets to "no intent recorded": replaying a half-parsed intent to the
        // service would be worse than replaying none.
        current.service_intent_json =
            storable_json_blob_or_empty("service_intent_json", self.service_intent_json);
        current.show_bluetooth_adapters = self.show_bluetooth_adapters;
        current.show_audit_tab = self.show_audit_tab;
        // Out-of-range (including the 0 an older QML build emits) keeps whatever
        // is already stored rather than resetting the user's chosen cadence.
        if (nrr_ui_support::ui_preferences::SETTINGS_AUTOSAVE_MIN_SECS
            ..=nrr_ui_support::ui_preferences::SETTINGS_AUTOSAVE_MAX_SECS)
            .contains(&self.settings_autosave_secs)
        {
            current.settings_autosave_secs = self.settings_autosave_secs;
        }
        current.admin_auto_revoke_disabled = self.admin_auto_revoke_disabled;
        // Same out-of-range rule as the autosave cadence above.
        if (nrr_ui_support::ui_preferences::ADMIN_AUTO_REVOKE_MIN_MINUTES
            ..=nrr_ui_support::ui_preferences::ADMIN_AUTO_REVOKE_MAX_MINUTES)
            .contains(&self.admin_auto_revoke_minutes)
        {
            current.admin_auto_revoke_minutes = self.admin_auto_revoke_minutes;
        }
        current.allow_mode_a_killswitch = self.allow_mode_a_killswitch;
        current.routing_detailed_mode = self.routing_detailed_mode;
        current.show_virtual_machines_section = self.show_virtual_machines_section;
        current.show_remembered_adapters = self.show_remembered_adapters;
        current.auto_confirm_adapter_id_change = self.auto_confirm_adapter_id_change;
        // Block-all banner opt-out (device-local display pref).
        current.warn_kill_switch_block_all = self.warn_kill_switch_block_all;
        // Block-all banner acknowledgement (device-local display state).
        current.kill_switch_banner_acknowledged = self.kill_switch_banner_acknowledged;
        // "Additional adapter not found" banner acknowledgement (device-local).
        current.missing_secondary_banner_acknowledged = self.missing_secondary_banner_acknowledged;
        // Traffic-statistics period slug. Non-empty gate so an older QML build
        // that omits the key keeps the stored value.
        if !self.traffic_stats_period.trim().is_empty() {
            current.traffic_stats_period = self.traffic_stats_period;
        }
        // Only a known unit slug is stored, so neither an older client nor a
        // typo can leave the panel pointing at a unit the exporter cannot use.
        if nrr_ui_support::ui_preferences::TRAFFIC_EXPORT_UNITS
            .contains(&self.traffic_export_unit.as_str())
        {
            current.traffic_export_unit = self.traffic_export_unit;
        }
        // Support-archive privacy tier: same allow-list gate, so neither an
        // older client nor a typo can request a tier the archive writer does
        // not implement. An absent key arrives as the empty string and is
        // rejected here, which keeps the stored value.
        if nrr_ui_support::ui_preferences::DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS
            .contains(&self.diagnostics_archive_redaction_level.as_str())
        {
            current.diagnostics_archive_redaction_level = self.diagnostics_archive_redaction_level;
        }
        // "Current session only" archive scope (device-local display state).
        current.diagnostics_archive_session_only = self.diagnostics_archive_session_only;
        // Raw-log attachment cap (MiB, `0` = unlimited). Key absent (older QML
        // build) → keep the stored value.
        if let Some(mib) = self.archive_log_budget_mib {
            current.archive_log_budget_mib = mib;
        }
        // Key present → take the value (single line only; the signature
        // is `|`-joined exe patterns and must not break the line-oriented
        // prefs file); key absent (older QML) → keep stored.
        if let Some(sig) = self.unenforced_apps_ack_sig {
            current.unenforced_apps_ack_signature = storable_line_or(
                "unenforced_apps_ack_signature",
                sig,
                current.unenforced_apps_ack_signature,
            );
        }
        // Same shape as the signature above: single line only, absent key
        // keeps what is stored.
        if let Some(sig) = self.rules_overlap_keep_sig {
            current.rules_overlap_keep_signature = storable_line_or(
                "rules_overlap_keep_signature",
                sig,
                current.rules_overlap_keep_signature,
            );
        }
        if let Some(sig) = self.route_overlaps_confirmed_sig {
            current.route_overlaps_confirmed_signature = storable_line_or(
                "route_overlaps_confirmed_signature",
                sig,
                current.route_overlaps_confirmed_signature,
            );
        }
        // Key present → take the value (single line only, so the
        // line-oriented prefs file stays intact); key absent (older QML) →
        // keep stored.
        if let Some(path) = self.confirmed_vpn_exe_path {
            current.confirmed_vpn_exe_path = storable_line_or(
                "confirmed_vpn_exe_path",
                path,
                current.confirmed_vpn_exe_path,
            );
        }
        // Key present → take the whole set (single line only); key
        // absent (older QML) → keep stored.
        if let Some(paths) = self.confirmed_vpn_exe_paths {
            current.confirmed_vpn_exe_paths = storable_line_or(
                "confirmed_vpn_exe_paths",
                paths,
                current.confirmed_vpn_exe_paths,
            );
        }
        if let Some(section) = self.last_opened_section.as_deref() {
            current.last_opened_section = section
                .parse::<AppSection>()
                .unwrap_or(current.last_opened_section);
        }

        // Carry through the eight file-source-state fields verbatim.
        // Empty-string round-trips through `parse_optional_string` as
        // None, so QML can either omit the key (serde-default None) or
        // send empty string (still None).
        current.last_saved_path_primary = self.last_saved_path_primary;
        current.last_saved_path_secondary = self.last_saved_path_secondary;
        current.last_loaded_path_primary = self.last_loaded_path_primary;
        current.last_loaded_path_secondary = self.last_loaded_path_secondary;
        current.auto_open_on_launch_path_primary = self.auto_open_on_launch_path_primary;
        current.auto_open_on_launch_path_secondary = self.auto_open_on_launch_path_secondary;
        current.last_file_synced_revision_id_primary = self.last_file_synced_revision_id_primary;
        current.last_file_synced_revision_id_secondary =
            self.last_file_synced_revision_id_secondary;
        current.last_file_synced_hash_primary = self.last_file_synced_hash_primary;
        current.last_file_synced_hash_secondary = self.last_file_synced_hash_secondary;
        current.service_install_uac_declined_at_epoch = self.service_install_uac_declined_at_epoch;
        current.service_install_uac_declined_count = self.service_install_uac_declined_count;
        current.service_install_prompt_suppressed = self.service_install_prompt_suppressed;
        current.auto_load_rules_on_launch = self.auto_load_rules_on_launch;
        current.export_include_comments = self.export_include_comments;
        current.import_only_active = self.import_only_active;
        current.compat_banner_mode = allowed_slug_or(
            &self.compat_banner_mode,
            &COMPAT_BANNER_MODES,
            &current.compat_banner_mode,
        );
        current.update_page_url = self.update_page_url;
        current.show_bundled_presets = self.show_bundled_presets;
        // Key present → take the value (single line only, so the
        // line-oriented prefs file stays intact); key absent (older QML) →
        // keep the folder the user configured.
        if let Some(dir) = self.user_presets_dir {
            if !dir.contains(['\n', '\r']) {
                current.user_presets_dir = dir;
            }
        }
        // Same contract for the remembered set: present → take it (single line
        // only), absent → keep what the user picked in an earlier session.
        if let Some(selected) = self.selected_preset_set {
            if !selected.contains(['\n', '\r']) {
                current.selected_preset_set = selected;
            }
        }
        current.allow_saving_into_bundled_presets = self.allow_saving_into_bundled_presets;
        current.rules_folder_suggestion_dismissed = self.rules_folder_suggestion_dismissed;
        current.merge_conflict_policy = allowed_slug_or(
            &self.merge_conflict_policy,
            &MERGE_CONFLICT_POLICIES,
            &current.merge_conflict_policy,
        );
        current.secondary_split_ack_adapter_name = self.secondary_split_ack_adapter_name;

        current
    }
}
