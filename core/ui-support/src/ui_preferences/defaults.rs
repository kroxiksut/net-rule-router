//! What a preferences file holds before the user has touched anything, and the
//! language detection that seeds it.
//!
//! A default here is not a suggestion: it is what an install that never opens
//! Settings runs on, so each one is chosen for the machine that never asks.

use super::*;
use nrr_platform_api::system_locale::SystemLocalePort;
use std::collections::BTreeSet;

// The route-policy fields start at their type defaults, like every other one.
// They are the application's own store and what the window shows while the
// service is stopped — not a legacy shape to be read past.
impl Default for UiPreferences {
    fn default() -> Self {
        Self::with_language(detected_system_language())
    }
}

impl UiPreferences {
    /// The defaults for a known language. The parser starts here with no
    /// language at all, so a file that names one never asks the system.
    pub(super) fn with_language(language: String) -> Self {
        let (route_primary_label, route_secondary_label) = default_route_labels(&language);
        Self {
            launch_window_on_startup: true,
            minimize_to_tray_instead_of_close: true,
            show_notifications: true,
            notify_suggestion_changes: true,
            notify_block_notices: true,
            notify_rule_duplicates: true,
            hide_block_notice_addresses: false,
            tray_notice_opacity_percent: 100,
            reopen_last_section_on_startup: true,
            first_run_completed: false,
            accepted_eula_version: nrr_shared::eula::EULA_NOT_ACCEPTED,
            theme_mode: ThemeMode::System,
            accessibility_high_contrast: false,
            accessibility_ui_font_scale_percent: 100,
            accessibility_system_font: SystemFontFamily::SystemDefault,
            accessibility_enhanced_focus_indicator: false,
            accessibility_simplified_labels: false,
            tooltips_enabled: true,
            language,
            route_primary_label,
            route_secondary_label,
            show_bluetooth_adapters: false,
            show_audit_tab: false,
            settings_autosave_secs: SETTINGS_AUTOSAVE_DEFAULT_SECS,
            admin_auto_revoke_disabled: false,
            admin_auto_revoke_minutes: ADMIN_AUTO_REVOKE_DEFAULT_MINUTES,
            allow_mode_a_killswitch: false,
            routing_detailed_mode: false,
            show_virtual_machines_section: false,
            app_groups_offer_dismissed: false,
            show_remembered_adapters: true,
            auto_confirm_adapter_id_change: true,
            warn_kill_switch_block_all: true,
            kill_switch_banner_acknowledged: false,
            missing_secondary_banner_acknowledged: false,
            traffic_stats_period: TRAFFIC_STATS_PERIOD_DEFAULT.to_string(),
            traffic_export_unit: TRAFFIC_EXPORT_UNIT_DEFAULT.to_string(),
            diagnostics_archive_redaction_level: DIAGNOSTICS_ARCHIVE_REDACTION_LEVEL_DEFAULT
                .to_string(),
            diagnostics_archive_session_only: true,
            archive_log_budget_mib: 0,
            unenforced_apps_ack_signature: String::new(),
            rules_overlap_keep_signature: String::new(),
            route_overlaps_confirmed_signature: String::new(),
            confirmed_vpn_exe_path: String::new(),
            confirmed_vpn_exe_paths: String::new(),
            selected_primary_interface_id: String::new(),
            selected_primary_interface_name: String::new(),
            primary_role_user_confirmed: false,
            selected_secondary_interface_id: String::new(),
            selected_secondary_interface_name: String::new(),
            secondary_role_user_confirmed: false,
            route_behavior_mode: RouteBehaviorMode::default_when_secondary_unbound(),
            // Device-local mirrors of per-SID policy toggles. Defaults match
            // the service DB defaults so a fresh install (or post-wipe seed)
            // starts neutral. Subdomain coverage defaults ON (matches the
            // service default); widening only adds coverage towards the
            // route the rule already names.
            route_include_subdomains: true,
            route_shared_ip_policy: SHARED_IP_POLICY_DEFAULT.to_string(),
            route_kill_switch_block_all: false,
            route_kill_switch_fail_closed: true,
            route_kill_switch_protocols: u32::from(
                nrr_shared::ipc_payloads::KILL_SWITCH_PROTOCOLS_ALL,
            ),
            route_kill_switch_enabled: false,
            route_allow_dns_over_primary: true,
            // Matches the service default (leak protection holds even while
            // the pin set is incomplete) and the hosts-bypass default.
            route_mode_a_coverage_strategy: route_mode_a_coverage_strategy_default(),
            route_resolve_hosts_bypass: true,
            // Kept in sync with `EnforcementMode::default().as_slug()`.
            route_enforcement_mode: nrr_shared::ipc_payloads::enforcement_mode_default(),
            route_liveness_window_secs: 0,
            route_pending_offline_json: String::new(),
            allow_saving_into_bundled_presets: false,
            rules_folder_suggestion_dismissed: false,
            cache_table_column_widths: String::new(),
            service_backed_mirror_json: String::new(),
            service_intent_json: String::new(),
            last_opened_section: AppSection::InterfacesAndRoutes,
            rules_view_sort: RulesViewSort::default(),
            rules_enabled_filter: RulesEnabledFilter::default(),
            rules_type_filter: RulesTypeFilter::default(),
            rules_file_change_behavior: RulesFileChangeBehavior::default(),
            // File-source state defaults. All None until the user performs
            // their first import / export.
            last_saved_path_primary: None,
            last_saved_path_secondary: None,
            last_loaded_path_primary: None,
            last_loaded_path_secondary: None,
            auto_open_on_launch_path_primary: None,
            auto_open_on_launch_path_secondary: None,
            service_install_uac_declined_at_epoch: None,
            service_install_uac_declined_count: 0,
            service_install_prompt_suppressed: false,
            // New toggles default to the pre-existing behaviour (auto-load
            // on, comments on, banner auto, no custom URL).
            auto_load_rules_on_launch: true,
            export_include_comments: true,
            import_only_active: true,
            compat_banner_mode: String::from(COMPAT_BANNER_MODE_DEFAULT),
            update_page_url: String::new(),
            update_check_enabled: true,
            update_check_interval_days: UPDATE_CHECK_INTERVAL_DEFAULT_DAYS,
            dismissed_update_version: String::new(),
            show_bundled_presets: true,
            // Empty means "list the rule sets shipped with the app".
            user_presets_dir: String::new(),
            // Empty means "the user has not picked a set yet", which is the only
            // state where the shipped-set list may choose one by system locale.
            selected_preset_set: String::new(),
            secondary_split_ack_adapter_name: String::new(),
            // The safe interactive policy: the merge keeps both sides and asks
            // the user to resolve conflicts.
            merge_conflict_policy: String::from(MERGE_CONFLICT_POLICY_DEFAULT),
            forward_compat: ForwardCompat::default(),
        }
    }
}

/// Default slug for the `route_mode_a_coverage_strategy` mirror. This is a
/// MIRROR of a service-owned policy field, so it never spells the slug itself —
/// it defers to the wire default in `nrr-shared`, which is normative.
fn route_mode_a_coverage_strategy_default() -> String {
    nrr_shared::ipc_payloads::mode_a_coverage_strategy_default()
}

/// Clamp the secondary tunnel liveness window (seconds) to the backend
/// contract: `0` stays `0` (disabled — the probe never fail-closes); any
/// non-zero value is clamped to `[5, 3600]`. Single source of truth shared by
/// the parser and any future serde surface.
pub(super) fn clamp_liveness_window_secs(value: u32) -> u32 {
    if value == 0 {
        0
    } else {
        value.clamp(5, 3600)
    }
}

pub(super) fn default_route_labels(language: &str) -> (String, String) {
    let base = language
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if base == "ru" {
        ("Основной".to_string(), "Дополнительный".to_string())
    } else {
        ("Primary".to_string(), "Secondary".to_string())
    }
}

/// The display-language probe this process should use, installed by the
/// surfaces for the same reason as the theme probe: this crate must not name
/// an OS. Nothing installed = English.
static SYSTEM_LOCALE_PORT: OnceLock<Box<dyn SystemLocalePort>> = OnceLock::new();

/// Installs the process-wide display-language probe. The first call wins.
/// Must precede the first preferences load: the answer is cached for the
/// process.
pub fn install_system_locale_port(port: Box<dyn SystemLocalePort>) {
    let _ = SYSTEM_LOCALE_PORT.set(port);
}

pub(super) fn detected_system_language() -> String {
    static DETECTED_LANGUAGE: OnceLock<String> = OnceLock::new();
    DETECTED_LANGUAGE
        .get_or_init(|| {
            detect_system_language_with(
                env::var("NRR_UI_LANGUAGE").ok().as_deref(),
                SYSTEM_LOCALE_PORT.get().map(|port| &**port),
            )
        })
        .clone()
}

/// `override_hint` is the product's own `NRR_UI_LANGUAGE`; it outranks the OS.
///
/// The port hands back the host's raw candidates in ITS OWN precedence
/// order (display language before regional format on Windows, `LANGUAGE`'s
/// list before `LC_ALL`/`LC_MESSAGES`/`LANG` on Linux) and this function
/// walks them to the first one this build has a translation for. A
/// candidate that exists but is untranslated is skipped, never widened to a
/// later, unrelated candidate that happens to be translated (a Windows
/// regional-format locale must not stand in for an untranslated UI
/// language) — the walk only continues because the port itself already
/// decided that candidate belongs after the ones before it.
pub(super) fn detect_system_language_with(
    override_hint: Option<&str>,
    port: Option<&dyn SystemLocalePort>,
) -> String {
    if let Some(hint) = override_hint.and_then(parse_language_hint) {
        return hint;
    }
    let candidates = port
        .map(SystemLocalePort::ui_language_candidates)
        .unwrap_or_default();
    first_translated_candidate(&candidates)
}

pub fn canonicalize_language_id(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    let trimmed = normalized
        .split('.')
        .next()
        .unwrap_or_default()
        .split('@')
        .next()
        .unwrap_or_default()
        .trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn parse_language_hint(value: &str) -> Option<String> {
    let normalized = canonicalize_language_id(value)?;
    Some(preferred_available_language(&normalized))
}

/// Base language subtags of CIS system locales that have no bundled
/// translation of their own. Russian is
/// the regionally-understood default for these; every other unmatched locale
/// falls back to English. Deliberately excludes `ro` (base subtag cannot
/// distinguish Moldova from Romania) and `ka` (Georgia).
const CIS_RU_FALLBACK_LANGS: &[&str] = &["be", "uk", "kk", "ky", "uz", "tg", "tk", "az", "hy"];

/// The set of locale ids this build ships a translation for, read from disk
/// and validated once per process. The catalogue only changes by dropping a
/// file into the locales directory, which per the language policy takes an
/// app restart to be seen at all — re-validating it on every language
/// lookup (including several during a single startup) bought nothing.
fn available_locale_ids() -> &'static BTreeSet<String> {
    static IDS: OnceLock<BTreeSet<String>> = OnceLock::new();
    IDS.get_or_init(|| {
        #[cfg(test)]
        LOCALE_CATALOG_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        load_locale_catalog().into_keys().collect()
    })
}

#[cfg(test)]
pub(super) static LOCALE_CATALOG_READS: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// Whether `requested` (already lowercased, `_`/`.`/`@` stripped) is a
/// language this build ships a translation for, and under which id. Returns
/// `None` rather than guessing at a fallback — the caller decides what an
/// untranslated candidate means (skip it and try the next one, or give up).
fn matched_available_language(ids: &BTreeSet<String>, requested: &str) -> Option<String> {
    if ids.contains(requested) {
        return Some(requested.to_string());
    }

    let base = requested
        .split('-')
        .next()
        .filter(|item| !item.is_empty())
        .unwrap_or("en");
    if ids.contains(base) {
        return Some(base.to_string());
    }

    // CIS locales without a bundled translation default to Russian (both
    // the app UI and the user agreement follow this choice; one button in
    // the agreement window switches everything to English).
    if CIS_RU_FALLBACK_LANGS.contains(&base) && ids.contains("ru") {
        return Some("ru".to_string());
    }

    None
}

fn fallback_language(ids: &BTreeSet<String>) -> String {
    if ids.contains("en") {
        "en".to_string()
    } else {
        ids.iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "en".to_string())
    }
}

pub(super) fn preferred_available_language(requested: &str) -> String {
    let ids = available_locale_ids();
    matched_available_language(ids, requested).unwrap_or_else(|| fallback_language(ids))
}

/// Walks ordered system-language candidates (as the port supplied them, most
/// preferred first) and returns the first one this build has a translation
/// for. None being translated lands on English (or whatever the catalogue
/// offers) — never on a later candidate the port only offered as a
/// less-preferred fallback of its own (see `detect_system_language_with`).
fn first_translated_candidate(candidates: &[String]) -> String {
    let ids = available_locale_ids();
    candidates
        .iter()
        .filter_map(|raw| canonicalize_language_id(raw))
        .find_map(|candidate| matched_available_language(ids, &candidate))
        .unwrap_or_else(|| fallback_language(ids))
}
