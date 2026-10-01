use super::*;

impl QtPreferencesPayload {
    // `apply_over` writes the adapter-binding fields back into
    // `UiPreferences`: the app's own store of what the service enforces per
    // SID, and what every panel shows while the service is stopped.
    pub(super) fn apply_over(self, mut current: UiPreferences) -> UiPreferences {
        // Absent means "not reported", never "set it to the type default":
        // every field keeps the stored value when its key is missing.
        if let Some(v) = self.launch_window_on_startup {
            current.launch_window_on_startup = v;
        }
        if let Some(v) = self.minimize_to_tray_instead_of_close {
            current.minimize_to_tray_instead_of_close = v;
        }
        if let Some(v) = self.show_notifications {
            current.show_notifications = v;
        }
        if let Some(v) = self.notify_suggestion_changes {
            current.notify_suggestion_changes = v;
        }
        if let Some(v) = self.notify_block_notices {
            current.notify_block_notices = v;
        }
        if let Some(v) = self.notify_rule_duplicates {
            current.notify_rule_duplicates = v;
        }
        if let Some(v) = self.hide_block_notice_addresses {
            current.hide_block_notice_addresses = v;
        }
        if let Some(percent) = self.tray_notice_opacity_percent {
            current.tray_notice_opacity_percent = percent.clamp(
                nrr_ui_support::ui_preferences::TRAY_NOTICE_OPACITY_MIN_PERCENT,
                nrr_ui_support::ui_preferences::TRAY_NOTICE_OPACITY_MAX_PERCENT,
            );
        }
        if let Some(v) = self.reopen_last_section_on_startup {
            current.reopen_last_section_on_startup = v;
        }
        if let Some(v) = self.first_run_completed {
            current.first_run_completed = v;
        }
        if let Some(version) = self.accepted_eula_version {
            current.accepted_eula_version = version;
        }

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
        if let Some(id) = self.selected_primary_interface_id {
            current.selected_primary_interface_id = id;
        }
        if let Some(name) = self.selected_primary_interface_name {
            current.selected_primary_interface_name = name;
        }
        if let Some(v) = self.primary_role_user_confirmed {
            current.primary_role_user_confirmed = v;
        }
        if let Some(id) = self.selected_secondary_interface_id {
            current.selected_secondary_interface_id = id;
        }
        if let Some(name) = self.selected_secondary_interface_name {
            current.selected_secondary_interface_name = name;
        }
        if let Some(v) = self.secondary_role_user_confirmed {
            current.secondary_role_user_confirmed = v;
        }
        if let Some(mode) = self.route_behavior_mode.as_deref() {
            current.route_behavior_mode = mode
                .parse::<RouteBehaviorMode>()
                .unwrap_or(current.route_behavior_mode);
        }
        // Policy-toggle mirrors. A slug or mask the file parser would refuse
        // keeps the stored value, so what is kept all session is what a
        // wiped service is reseeded with.
        if let Some(v) = self.route_include_subdomains {
            current.route_include_subdomains = v;
        }
        if let Some(slug) = self.route_shared_ip_policy {
            current.route_shared_ip_policy = allowed_slug_or(
                &slug,
                &nrr_ui_support::ui_preferences::SHARED_IP_POLICIES,
                &current.route_shared_ip_policy,
            );
        }
        if let Some(v) = self.route_kill_switch_block_all {
            current.route_kill_switch_block_all = v;
        }
        if let Some(v) = self.route_kill_switch_fail_closed {
            current.route_kill_switch_fail_closed = v;
        }
        if let Some(mask) = self.route_kill_switch_protocols.filter(|&mask| {
            u16::try_from(mask).is_ok_and(nrr_shared::ipc_payloads::is_valid_kill_switch_protocols)
        }) {
            current.route_kill_switch_protocols = mask;
        }
        if let Some(v) = self.route_kill_switch_enabled {
            current.route_kill_switch_enabled = v;
        }
        if let Some(v) = self.route_allow_dns_over_primary {
            current.route_allow_dns_over_primary = v;
        }
        // An unknown slug from a divergent QML build keeps the stored value.
        if let Some(slug) = self.route_mode_a_coverage_strategy.filter(|slug| {
            matches!(
                slug.as_str(),
                "per-ip" | "fail-closed-unknown" | "zone-widening"
            )
        }) {
            current.route_mode_a_coverage_strategy = slug;
        }
        if let Some(v) = self.route_resolve_hosts_bypass {
            current.route_resolve_hosts_bypass = v;
        }
        if let Some(slug) = self
            .route_enforcement_mode
            .filter(|slug| matches!(slug.as_str(), "reactive" | "resolver"))
        {
            current.route_enforcement_mode = slug;
        }
        // `0` stays `0` (disabled); any other value is clamped to `[5, 3600]`.
        if let Some(secs) = self.route_liveness_window_secs {
            current.route_liveness_window_secs = if secs == 0 { 0 } else { secs.clamp(5, 3600) };
        }
        // Blobs: an explicit empty string is "nothing pending / mirrored /
        // intended" and clears the stored value.
        if let Some(blob) = self.route_pending_offline_json {
            current.route_pending_offline_json =
                storable_json_blob_or_empty("route_pending_offline_json", blob);
        }
        if let Some(blob) = self.cache_table_column_widths {
            current.cache_table_column_widths =
                storable_json_blob_or_empty("cache_table_column_widths", blob);
        }
        if let Some(blob) = self.service_backed_mirror_json {
            current.service_backed_mirror_json =
                storable_json_blob_or_empty("service_backed_mirror_json", blob);
        }
        // A blob failing the gate resets to "no intent recorded": replaying a
        // half-parsed intent to the service would be worse than replaying none.
        if let Some(blob) = self.service_intent_json {
            current.service_intent_json = storable_json_blob_or_empty("service_intent_json", blob);
        }
        if let Some(v) = self.show_bluetooth_adapters {
            current.show_bluetooth_adapters = v;
        }
        if let Some(v) = self.show_audit_tab {
            current.show_audit_tab = v;
        }
        // Out of range (including the 0 an older QML build emits) keeps whatever
        // is already stored rather than resetting the user's chosen cadence.
        if let Some(secs) = self.settings_autosave_secs.filter(|secs| {
            (nrr_ui_support::ui_preferences::SETTINGS_AUTOSAVE_MIN_SECS
                ..=nrr_ui_support::ui_preferences::SETTINGS_AUTOSAVE_MAX_SECS)
                .contains(secs)
        }) {
            current.settings_autosave_secs = secs;
        }
        if let Some(v) = self.admin_auto_revoke_disabled {
            current.admin_auto_revoke_disabled = v;
        }
        if let Some(minutes) = self.admin_auto_revoke_minutes.filter(|minutes| {
            (nrr_ui_support::ui_preferences::ADMIN_AUTO_REVOKE_MIN_MINUTES
                ..=nrr_ui_support::ui_preferences::ADMIN_AUTO_REVOKE_MAX_MINUTES)
                .contains(minutes)
        }) {
            current.admin_auto_revoke_minutes = minutes;
        }
        if let Some(v) = self.allow_mode_a_killswitch {
            current.allow_mode_a_killswitch = v;
        }
        if let Some(v) = self.routing_detailed_mode {
            current.routing_detailed_mode = v;
        }
        if let Some(v) = self.show_virtual_machines_section {
            current.show_virtual_machines_section = v;
        }
        if let Some(v) = self.app_groups_offer_dismissed {
            current.app_groups_offer_dismissed = v;
        }
        if let Some(v) = self.show_remembered_adapters {
            current.show_remembered_adapters = v;
        }
        if let Some(v) = self.auto_confirm_adapter_id_change {
            current.auto_confirm_adapter_id_change = v;
        }
        if let Some(v) = self.warn_kill_switch_block_all {
            current.warn_kill_switch_block_all = v;
        }
        if let Some(v) = self.kill_switch_banner_acknowledged {
            current.kill_switch_banner_acknowledged = v;
        }
        if let Some(v) = self.missing_secondary_banner_acknowledged {
            current.missing_secondary_banner_acknowledged = v;
        }
        // An unknown slug keeps the stored value.
        if let Some(period) = self.traffic_stats_period {
            current.traffic_stats_period = allowed_slug_or(
                &period,
                &nrr_ui_support::ui_preferences::TRAFFIC_STATS_PERIODS,
                &current.traffic_stats_period,
            );
        }
        // Only a known unit slug is stored, so neither an older client nor a
        // typo can leave the panel pointing at a unit the exporter cannot use.
        if let Some(unit) = self.traffic_export_unit.filter(|unit| {
            nrr_ui_support::ui_preferences::TRAFFIC_EXPORT_UNITS.contains(&unit.as_str())
        }) {
            current.traffic_export_unit = unit;
        }
        // Same allow-list gate: no tier the archive writer does not implement.
        if let Some(level) = self.diagnostics_archive_redaction_level.filter(|level| {
            nrr_ui_support::ui_preferences::DIAGNOSTICS_ARCHIVE_REDACTION_LEVELS
                .contains(&level.as_str())
        }) {
            current.diagnostics_archive_redaction_level = level;
        }
        if let Some(v) = self.diagnostics_archive_session_only {
            current.diagnostics_archive_session_only = v;
        }
        if let Some(mib) = self.archive_log_budget_mib {
            current.archive_log_budget_mib = mib;
        }
        // Signatures and paths stay single-line so the line-oriented prefs
        // file stays intact.
        if let Some(sig) = self.unenforced_apps_ack_sig {
            current.unenforced_apps_ack_signature = storable_line_or(
                "unenforced_apps_ack_signature",
                sig,
                current.unenforced_apps_ack_signature,
            );
        }
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
        if let Some(path) = self.confirmed_vpn_exe_path {
            current.confirmed_vpn_exe_path = storable_line_or(
                "confirmed_vpn_exe_path",
                path,
                current.confirmed_vpn_exe_path,
            );
        }
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

        // File-source state, verbatim when reported. An empty string reads
        // back from the file as `None`.
        let file_source = [
            (
                self.last_saved_path_primary,
                &mut current.last_saved_path_primary,
            ),
            (
                self.last_saved_path_secondary,
                &mut current.last_saved_path_secondary,
            ),
            (
                self.last_loaded_path_primary,
                &mut current.last_loaded_path_primary,
            ),
            (
                self.last_loaded_path_secondary,
                &mut current.last_loaded_path_secondary,
            ),
            (
                self.auto_open_on_launch_path_primary,
                &mut current.auto_open_on_launch_path_primary,
            ),
            (
                self.auto_open_on_launch_path_secondary,
                &mut current.auto_open_on_launch_path_secondary,
            ),
        ];
        for (reported, stored) in file_source {
            if let Some(value) = reported {
                *stored = value;
            }
        }
        if let Some(at) = self.service_install_uac_declined_at_epoch {
            current.service_install_uac_declined_at_epoch = at;
        }
        if let Some(count) = self.service_install_uac_declined_count {
            current.service_install_uac_declined_count = count;
        }
        if let Some(v) = self.service_install_prompt_suppressed {
            current.service_install_prompt_suppressed = v;
        }
        if let Some(v) = self.auto_load_rules_on_launch {
            current.auto_load_rules_on_launch = v;
        }
        if let Some(v) = self.export_include_comments {
            current.export_include_comments = v;
        }
        if let Some(v) = self.import_only_active {
            current.import_only_active = v;
        }
        if let Some(mode) = self.compat_banner_mode {
            current.compat_banner_mode =
                allowed_slug_or(&mode, &COMPAT_BANNER_MODES, &current.compat_banner_mode);
        }
        if let Some(url) = self.update_page_url {
            current.update_page_url = url;
        }
        if let Some(enabled) = self.update_check_enabled {
            current.update_check_enabled = enabled;
        }
        if let Some(days) = self.update_check_interval_days {
            current.update_check_interval_days =
                nrr_ui_support::ui_preferences::clamp_update_check_interval_days(days);
        }
        if let Some(version) = self.dismissed_update_version {
            current.dismissed_update_version = storable_line_or(
                "dismissed_update_version",
                version,
                current.dismissed_update_version,
            );
        }
        if let Some(v) = self.show_bundled_presets {
            current.show_bundled_presets = v;
        }
        if let Some(dir) = self.user_presets_dir {
            if !dir.contains(['\n', '\r']) {
                current.user_presets_dir = dir;
            }
        }
        if let Some(selected) = self.selected_preset_set {
            if !selected.contains(['\n', '\r']) {
                current.selected_preset_set = selected;
            }
        }
        if let Some(v) = self.allow_saving_into_bundled_presets {
            current.allow_saving_into_bundled_presets = v;
        }
        if let Some(v) = self.rules_folder_suggestion_dismissed {
            current.rules_folder_suggestion_dismissed = v;
        }
        if let Some(policy) = self.merge_conflict_policy {
            current.merge_conflict_policy = allowed_slug_or(
                &policy,
                &MERGE_CONFLICT_POLICIES,
                &current.merge_conflict_policy,
            );
        }
        if let Some(name) = self.secondary_split_ack_adapter_name {
            current.secondary_split_ack_adapter_name = name;
        }

        current
    }
}
