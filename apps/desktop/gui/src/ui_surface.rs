use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, BackendProviderKind,
};
use nrr_application::mock_backend::network_interfaces::RouteSelectionRequest;
use nrr_application::mock_backend::rules::RulesScreenRequest;
use nrr_shared::launcher_rpc::HostAnswerDeadlines;
use nrr_shared::{
    resolve_catalog_text, AppSection, AppShellModel, LocaleLoadStatus, RouteBehaviorMode, ThemeMode,
};
use nrr_ui_support::first_run::FirstRunFlowSnapshot;
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::ui_preferences::{
    allowed_slug_or, canonicalize_language_id, storable_json_blob_or_empty, storable_line_or,
    SystemFontFamily, UiPreferences, COMPAT_BANNER_MODES, MERGE_CONFLICT_POLICIES,
};
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn resolve_icon_path() -> Option<PathBuf> {
    bundled_resource("assets/icons/app/icon-256.png")
}

/// A payload path the package ships with the binary, `/`-separated relative to
/// the package root: beside the executable and, in a debug build only, in the
/// checkout it was built from. Never a parent or the working directory, where
/// another local user can plant files.
fn bundled_resource(relative: &str) -> Option<PathBuf> {
    let executable_dir = env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(Path::to_path_buf));
    // `apps/desktop/gui` sits three levels below the checkout root.
    #[cfg(debug_assertions)]
    let checkout = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3);
    #[cfg(not(debug_assertions))]
    let checkout = None;
    find_bundled(executable_dir.as_deref(), checkout, relative)
}

fn find_bundled(
    executable_dir: Option<&Path>,
    checkout: Option<&Path>,
    relative: &str,
) -> Option<PathBuf> {
    executable_dir
        .into_iter()
        .chain(checkout)
        .map(|root| {
            relative
                .split('/')
                .fold(root.to_path_buf(), |path, segment| path.join(segment))
        })
        .find(|candidate| candidate.exists())
}

/// Emergency network-recovery script shipped beside the executable. Surfaced
/// so the licence screen can point at the real file instead of a path the user
/// has to find; `None` when the build does not carry `scripts/` (the in-app
/// "Restore network" button is the ordinary route either way).
fn resolve_reset_script_path() -> Option<PathBuf> {
    #[cfg(windows)]
    const RESET_SCRIPT: &str = "scripts/reset-network.ps1";
    #[cfg(not(windows))]
    const RESET_SCRIPT: &str = "scripts/reset-network.sh";

    bundled_resource(RESET_SCRIPT)
}

/// The console line that runs the recovery script, spelled the way this OS
/// spells it. Quoted: the shipped path may sit under "Program Files".
fn reset_script_command_line(path: &str) -> String {
    #[cfg(windows)]
    {
        format!("powershell -ExecutionPolicy Bypass -File \"{path}\"")
    }
    #[cfg(not(windows))]
    {
        format!("sudo bash \"{path}\"")
    }
}

/// URL of the service's operational-log directory (the `paths` SSOT), for
/// "Open logs folder"; its parent while the service has not written a log yet.
/// Offered whether or not THIS process can list it: the file manager asks for
/// the access itself. Never created here: the service owns it and its ACL. The
/// C++ host reads this same value from the launch context.
pub fn logs_folder_url() -> Option<String> {
    let dir = nrr_platform_api::paths::production_logs_dir()?;
    let existing = if dir.is_dir() {
        dir
    } else {
        dir.parent().filter(|p| p.is_dir())?.to_path_buf()
    };
    Some(path_to_file_url(&existing))
}

/// Embedded: the package does not ship `LICENSE` as a file.
const LICENSE_EMBEDDED: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../LICENSE"));

fn load_license_text() -> String {
    LICENSE_EMBEDDED.to_string()
}

/// The Russian EULA, embedded at compile time so the agreement text is always
/// available regardless of how the binary is deployed. The runtime loader
/// prefers an on-disk locale-specific file (so an English `eula.en.md` added
/// later is picked up without a rebuild) and falls back to this.
const EULA_RU_EMBEDDED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../docs/legal/eula.ru.md"
));

/// The English EULA, embedded like the Russian one.
const EULA_EN_EMBEDDED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../docs/legal/eula.en.md"
));

/// Load the end-user agreement text for the given UI language.
///
/// Resolution order: an on-disk `eula.<lang>.md` for the requested base
/// language, then the compiled-in text for that language (`ru` and `en`
/// are both embedded). Only the base language subtag is used (`en-US` →
/// `en`); any language other than `ru` resolves to the English text —
/// only ru/CIS locales see Russian, and that choice is made upstream by
/// `preferred_available_language`.
fn load_eula_text(language: &str) -> String {
    let lang = language
        .split(['-', '_'])
        .next()
        .unwrap_or("ru")
        .to_ascii_lowercase();
    let (name, embedded) = if lang == "ru" {
        ("eula.ru.md", EULA_RU_EMBEDDED)
    } else {
        ("eula.en.md", EULA_EN_EMBEDDED)
    };
    if let Some(path) = bundled_resource(&format!("docs/legal/{name}")) {
        if let Ok(content) = fs::read_to_string(path) {
            if !content.trim().is_empty() {
                return content;
            }
        }
    }
    embedded.to_string()
}

// `write_qt_context_file_at` reads the legacy `UiPreferences` policy
// fields to build the initial QML context. Once `BackendFacadeHandle`
// is wired, the GUI sources route bindings/mode from IPC
// `SnapshotInitial.routePolicy` instead; until then this function
// still consumes the deprecated fields, and the launcher's migration
// flow keeps the on-disk values in sync with what the service has
// stored.
/// How long the launcher may spend on backend snapshots before the window
/// exists.
///
/// Measured against the SUM of the calls, because that is what the user waits
/// through. Chosen so a healthy service (single-digit milliseconds per call)
/// never notices it, while a wedged one costs a couple of seconds instead of
/// twenty.
const COLD_START_BACKEND_BUDGET: std::time::Duration = std::time::Duration::from_millis(2500);

#[allow(clippy::too_many_arguments)] // context emitter threads the full UI surface
pub fn write_qt_context_file_at(
    file_path: &Path,
    shell: &AppShellModel,
    section_to_open: AppSection,
    preferences: UiPreferences,
    first_run: &FirstRunFlowSnapshot,
    request: &crate::app_shell::LaunchRequest,
    backend: &dyn BackendFacade,
    backend_status: &BackendConnectionStatus,
    service_started_on_launch: bool,
    answer_deadlines: &HostAnswerDeadlines,
) -> Result<(), String> {
    // One pass over the locale files, not three: each of the old calls loaded,
    // parsed and validated both files in full, and this emitter needs all three
    // of their results.
    let locales = nrr_shared::load_locale_state();
    let locale_catalog = locales.catalog;
    let locale_descriptors = locales.descriptors;
    let locale_reports = locales.reports;
    let rejected_locales = locale_reports
        .iter()
        .filter(|report| report.status == LocaleLoadStatus::Rejected)
        .collect::<Vec<_>>();
    let locales_with_warnings = locale_reports
        .iter()
        .filter(|report| report.status == LocaleLoadStatus::AcceptedWithWarnings)
        .collect::<Vec<_>>();
    let interfaces_request = RouteSelectionRequest {
        primary_candidate_id: if preferences.selected_primary_interface_id.trim().is_empty() {
            None
        } else {
            Some(preferences.selected_primary_interface_id.clone())
        },
        primary_candidate_name: if preferences
            .selected_primary_interface_name
            .trim()
            .is_empty()
        {
            None
        } else {
            Some(preferences.selected_primary_interface_name.clone())
        },
        primary_candidate_confirmed: preferences.primary_role_user_confirmed,
        secondary_candidate_id: if preferences
            .selected_secondary_interface_id
            .trim()
            .is_empty()
        {
            None
        } else {
            Some(preferences.selected_secondary_interface_id.clone())
        },
        secondary_candidate_name: if preferences
            .selected_secondary_interface_name
            .trim()
            .is_empty()
        {
            None
        } else {
            Some(preferences.selected_secondary_interface_name.clone())
        },
        secondary_candidate_confirmed: preferences.secondary_role_user_confirmed,
        behavior_mode: preferences.route_behavior_mode,
    };
    // Backend snapshots flow through `BackendFacade`. For mock /
    // preview-local providers, the methods delegate to the same
    // `preview_*` helpers. For the production `IpcBackendFacade`,
    // they round-trip to the running service when
    // `backend_status == Connected` and serve from a stale cache
    // (with `stale=true` flagged in the typed wrappers) on transient
    // disconnects. The launcher's `backend_status` argument drives the
    // QML banner; this function does not interpret it.
    // Every one of these blocks the launcher BEFORE the window exists, and each
    // carries its own IPC timeout — so a service that is slow (or absent) is
    // paid for in seconds of no window at all. The timings go to the launcher
    // log so the cost is measured rather than guessed.
    let mut cold_start_timings: Vec<(&'static str, u128)> = Vec::new();
    let mut timed = |name: &'static str, started: std::time::Instant| {
        cold_start_timings.push((name, started.elapsed().as_millis()));
    };
    // ONE budget for the whole pre-window block, not one timeout per call.
    // The user experiences the SUM: six calls with their own budgets added up
    // to 21 s of black screen against a wedged service. Once this is spent the
    // remaining snapshots are served locally — the same fallback the production
    // facade takes on an IPC failure — and `backendStatus` is degraded to
    // `Connecting`, so nothing on screen claims to have been verified against
    // the service. The GUI's own refresh fills in moments later.
    //
    // The bound is BUDGET + one call's timeout: a call already in flight cannot
    // be cut short from here, only the next one can be skipped.
    let cold_start_started = std::time::Instant::now();
    let mut budget_spent = false;
    let budget_left = |started: &std::time::Instant| started.elapsed() < COLD_START_BACKEND_BUDGET;

    let t = std::time::Instant::now();
    let interfaces_snapshot = if budget_left(&cold_start_started) {
        backend.interfaces_snapshot(interfaces_request)
    } else {
        budget_spent = true;
        nrr_application::mock_backend::network_interfaces::interfaces_routes_preview_snapshot(
            interfaces_request,
        )
    };
    timed("interfaces", t);
    let t = std::time::Instant::now();
    let rules_snapshot = if budget_left(&cold_start_started) {
        backend.rules_snapshot(RulesScreenRequest::default())
    } else {
        budget_spent = true;
        nrr_application::mock_backend::rules::rules_screen_preview_snapshot(
            RulesScreenRequest::default(),
        )
    };
    timed("rules", t);
    let t = std::time::Instant::now();
    // Out of budget there is no answer, so neither may read as a healthy
    // service: the same "unknown" the facade hands out on an IPC failure.
    let diagnostics_status = if budget_left(&cold_start_started) {
        backend.diagnostics_status_snapshot()
    } else {
        budget_spent = true;
        nrr_application::mock_backend::diagnostics::DiagnosticsStatusDto::unavailable()
    };
    timed("diagnostics", t);
    let t = std::time::Instant::now();
    let active_alerts = if budget_left(&cold_start_started) {
        backend.list_security_alerts(None)
    } else {
        budget_spent = true;
        nrr_application::mock_backend::diagnostics::SecurityAlertsView::unavailable()
    };
    timed("alerts", t);
    // Logs and audit are NOT fetched here. Both are paged screens the user
    // reaches by opening them, and `LogsSection` loads its own first page on
    // show — fetching them before the window exists bought nothing and could
    // cost two IPC timeouts of black screen on a slow or absent service. The
    // context keeps the shape, with an empty first page.
    let logs_page = nrr_application::mock_backend::logs::PageResult::<
        nrr_application::mock_backend::logs::LogEntryDto,
    >::empty();
    let audit_page = nrr_application::mock_backend::logs::PageResult::<
        nrr_application::mock_backend::logs::AuditEntryDto,
    >::empty();
    let total: u128 = cold_start_timings.iter().map(|(_, ms)| ms).sum();
    if budget_spent {
        println!(
            "NRR_LAUNCHER[cold-start] budget of {}ms spent — the rest is local, the window opens now and the GUI refreshes from the service",
            COLD_START_BACKEND_BUDGET.as_millis()
        );
    }
    println!(
        "NRR_LAUNCHER[cold-start] total={total}ms {}",
        cold_start_timings
            .iter()
            .map(|(name, ms)| format!("{name}={ms}ms"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let about = nrr_application::about_window_info();
    let resolved_theme = resolve_theme(preferences.theme_mode);
    let icon_file_url = resolve_icon_path()
        .as_ref()
        .map(|path| path_to_file_url(path));
    let logs_folder_url = logs_folder_url();
    let reset_script_path =
        resolve_reset_script_path().map(|path| path.to_string_lossy().into_owned());
    let reset_script_command = reset_script_path.as_deref().map(reset_script_command_line);
    let license_text = load_license_text();
    let eula_text = load_eula_text(&preferences.language);
    let locale_diagnostics = json!({
        "acceptedWithWarnings": locales_with_warnings.len(),
        "rejected": rejected_locales.len(),
        "reports": locale_reports.iter().map(|report| json!({
            "id": report.id,
            "fileName": report.file_name,
            "source": match report.source {
                nrr_shared::LocaleSource::Bundled => "bundled",
                nrr_shared::LocaleSource::User => "user",
            },
            "status": match report.status {
                LocaleLoadStatus::Accepted => "accepted",
                LocaleLoadStatus::AcceptedWithWarnings => "accepted-with-warnings",
                LocaleLoadStatus::Rejected => "rejected",
            },
            "warnings": report.warnings,
            "errors": report.errors,
        })).collect::<Vec<_>>(),
    });
    let interface_rows_json = interfaces_snapshot
        .rows
        .iter()
        .map(|row| {
            json!({
                "persistentId": row.persistent_id,
                "name": row.name,
                "description": row.interface_description,
                "type": row.interface_type,
                "kind": row.kind.slug(),
                "deviceTechnology": row.device_technology.map_or("", |tech| tech.slug()),
                "ip": row.local_ip,
                "gateway": row.gateway,
                "dns": row.dns_servers,
                "hasDefaultRoute": row.has_default_route,
                "availability": row.availability_status.title(),
                "selectedRole": row.selected_role.map(|role| match role {
                    nrr_shared::RouteRole::Primary => "primary",
                    nrr_shared::RouteRole::Secondary => "secondary",
                }),
                "routeState": row.route_state.title(),
                "isBluetoothLike": row.is_bluetooth_like,
                "observedFacts": {
                    "connectivityState": row.observed_facts.connectivity_state.title(),
                    "externalIpStatus": row.observed_facts.external_ip_status.title(),
                    "externalIp": row.observed_facts.external_ip,
                },
                "derivedAssessment": {
                    "vpnTunnelLikelihood": row.derived_assessment.vpn_tunnel_likelihood.title(),
                    "virtualInterfaceLikelihood": row
                        .derived_assessment
                        .virtual_interface_likelihood
                        .title(),
                    "serviceInterfaceLikelihood": row
                        .derived_assessment
                        .service_interface_likelihood
                        .title(),
                    "classification": row.derived_assessment.classification,
                    "confidencePercent": row.derived_assessment.confidence_percent,
                    "heuristicOnly": row.derived_assessment.heuristic_only,
                    "signals": row.derived_assessment.signals,
                },
                "recommendation": {
                    "class": row.recommendation.class.title(),
                    "confidence": row.recommendation.confidence.title(),
                    "advisoryOnly": row.recommendation.advisory_only,
                    "keySignals": row.recommendation.key_signals,
                    "excludedAlternatives": row.recommendation.excluded_alternatives,
                },
            })
        })
        .collect::<Vec<_>>();

    // The QML dialog uses the `FreeRuleType` slugs as ids and reads localized
    // titles via `rules.type.<id>`.
    // Validation status is the per-row verdict of `nrr-domain` — the one the
    // Add/Edit dialog is gated on, so a typed and an imported row are judged
    // alike.
    //
    // In production the parser-supplied status ships over IPC from the
    // service via `RulesListResponse.rows[i].validation_status`. The
    // in-place revalidation below is retained as a fallback for the
    // preview (mock) mode only, whose fixture (`nrr-mock-backend::rules`)
    // carries only valid match values today.
    // Demo rules are something the user asks for — the first-run wizard's
    // "use built-in demo rules", the Rules screen's "load demo rules" — never
    // something a launch hands them. A service-backed start therefore carries
    // NO rows: the table stays empty until the live revision arrives, and
    // stays empty for good if the user has no rules yet. Only a mock/preview
    // build still renders the preview seed; it has no service to read.
    let rules_rows_json: Vec<serde_json::Value> =
        if backend_provider_is_service_backed(backend.provider_kind()) {
            Vec::new()
        } else {
            rules_snapshot
                .rows
                .iter()
                .map(|row| {
                    let validation = nrr_application::rule_value_validation::validate_rule_value(
                        row.rule_type.slug(),
                        row.match_value,
                    );
                    json!({
                        "id": row.id,
                        "enabled": row.enabled,
                        "ruleType": row.rule_type.slug(),
                        "ruleTypeTitle": row.rule_type.title(),
                        "matchValue": row.match_value,
                        "targetRoute": match row.target_route {
                            nrr_shared::RouteRole::Primary => "primary",
                            nrr_shared::RouteRole::Secondary => "secondary",
                        },
                        "verify": false,
                        "comment": row.comment,
                        "validationStatus": validation.status_slug(),
                        "validationMessageKey": validation.message_key(),
                        "validationMessageArgs": validation.args(),
                    })
                })
                .collect()
        };
    // The empty-rules state is driven entirely by `EmptyState` in
    // `RulesSection.qml`; users see "Add your first rule" instead of a
    // pre-populated invalid example.

    // The rule-type list comes from the backend snapshot alone: a hardcoded
    // entry next to it showed that type twice in the Add-Rule dropdown.
    let mut supported_rule_types: Vec<serde_json::Value> = Vec::new();
    supported_rule_types.extend(rules_snapshot.supported_rule_types.iter().map(|rule_type| {
        json!({
            "id": rule_type.slug(),
            "title": rule_type.title(),
        })
    }));

    // Data we served locally was never verified against the service, so the
    // window must not claim a live connection. `Connecting` is the state the
    // GUI already renders honestly ("Not verified — the service isn't
    // reachable right now") and refreshes out of on its own.
    let effective_backend_status = if budget_spent && backend_status.is_connected() {
        BackendConnectionStatus::Connecting
    } else {
        backend_status.clone()
    };
    let backend_status_payload = backend_connection_status_to_payload(&effective_backend_status);
    let backend_service_backed = backend_provider_is_service_backed(backend.provider_kind());
    // Capability descriptor for the running OS. The QML renders
    // capability-driven (a section shows only when `supports.<feature>` is
    // true), so OS knowledge stays in Rust and never leaks into a
    // `Qt.platform.os` branch in QML.
    // First-run answers handed over before launch. Absent on an ordinary
    // install, which is the case the wizard exists for.
    let provisioning_payload = match crate::provisioning::load() {
        Some(loaded) => json!({
            "present": true,
            "sourcePath": loaded.source_path.display().to_string(),
            "completesFirstRun": loaded.answers.completes_first_run(),
            "primaryConnection": loaded.answers.primary_connection,
            "secondaryConnection": loaded.answers.secondary_connection,
            "killSwitch": loaded.answers.kill_switch,
            "dohLockdown": loaded.answers.doh_lockdown,
            "fakeIp": loaded.answers.fake_ip,
            "ruleSet": loaded.answers.rule_set,
            "language": loaded.answers.language,
        }),
        None => json!({ "present": false, "completesFirstRun": false }),
    };

    let mut platform_profile =
        serde_json::to_value(nrr_shared::platform_profile::PlatformProfile::current())
            .unwrap_or(serde_json::Value::Null);
    // Runtime enrichment: does the hosts file contain any real mapping
    // entry? On a stock machine it is comments-only and the GUI hides
    // the hosts affordances entirely. The pure classifier lives in
    // nrr-shared; the I/O stays here (the profile struct itself is pure).
    // Unreadable (locked/denied) or oversized (multi-MB ad-block list — which
    // by definition HAS entries) both default to `true`: when in doubt, show
    // the affordance rather than hide a live setting.
    if let serde_json::Value::Object(profile) = &mut platform_profile {
        let hosts_path = profile
            .get("hostsFilePath")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let has_entries = match std::fs::metadata(&hosts_path) {
            Ok(meta) if meta.len() > 4 * 1024 * 1024 => true,
            Ok(_) => std::fs::read_to_string(&hosts_path)
                .map(|content| nrr_shared::platform_profile::hosts_content_has_entries(&content))
                .unwrap_or(true),
            Err(_) => true,
        };
        profile.insert(
            "hostsFileHasEntries".to_string(),
            serde_json::Value::Bool(has_entries),
        );
    }

    let context = json!({
        "windowTitle": shell.main_window_shell.window_title,
        "entrySection": section_to_open.slug(),
        "backendStatus": backend_status_payload,
        // Whether the cold-start facade actually talks to the service. A
        // mock/preview launch reports `backendStatus.kind == "connected"`
        // without a service behind it, and the GUI must park routing changes
        // in that case instead of pretending they were applied.
        "backendServiceBacked": backend_service_backed,
        // The service was stopped and this launch started it again.
        "serviceStartedOnLaunch": service_started_on_launch,
        "iconFileUrl": icon_file_url,
        "platformProfile": platform_profile,
        // How long `RpcTransport.qml` waits for each answer; the launcher owns the budgets.
        "rpcAnswerDeadlines": answer_deadlines,
        // First-run answers supplied ahead of launch (installer payload, or a
        // file beside a portable copy). `completesFirstRun` is the wizard's
        // whole gate; the individual answers pre-fill it when it does open.
        "provisioning": provisioning_payload,
        "startupDialog": if request.open_license {
            Some("license")
        } else if request.open_about {
            Some("about")
        } else {
            None::<&str>
        },
        // Intent slug of the launch that produced this context ("open and
        // compare" on the tray's rules-drift notice, "safe disable", …). On a
        // warm launch it travels in the activation-request file instead; a cold
        // one has no window to hand it to, so it rides the context.
        "launchAction": request.action,
        "launchReason": request.reason,
        // Setting to scroll to and highlight, with its display-only context.
        "launchFocus": request.focus,
        "launchFocusContext": request.focus_context,
        "preferences": {
            "launchWindowOnStartup": preferences.launch_window_on_startup,
            "minimizeToTrayInsteadOfClose": preferences.minimize_to_tray_instead_of_close,
            "showNotifications": preferences.show_notifications,
            "notifySuggestionChanges": preferences.notify_suggestion_changes,
            "notifyBlockNotices": preferences.notify_block_notices,
            "notifyRuleDuplicates": preferences.notify_rule_duplicates,
            "trayNoticeOpacityPercent": preferences.tray_notice_opacity_percent,
            "hideBlockNoticeAddresses": preferences.hide_block_notice_addresses,
            "routingDetailedMode": preferences.routing_detailed_mode,
            // Experimental opt-in that reveals the Rules -> Virtual machines
            // screen (default off). Device-local.
            "showVirtualMachinesSection": preferences.show_virtual_machines_section,
            "appGroupsOfferDismissed": preferences.app_groups_offer_dismissed,
            "reopenLastSectionOnStartup": preferences.reopen_last_section_on_startup,
            "firstRunCompleted": preferences.first_run_completed,
            "acceptedEulaVersion": preferences.accepted_eula_version,
            "themeMode": preferences.theme_mode.slug(),
            "effectiveThemeMode": resolved_theme.effective_mode.slug(),
            "accessibilityHighContrast": preferences.accessibility_high_contrast,
            "fontScalePercent": preferences.accessibility_ui_font_scale_percent,
            "systemFont": preferences.accessibility_system_font.slug(),
            "enhancedFocus": preferences.accessibility_enhanced_focus_indicator,
            "simplifiedLabels": preferences.accessibility_simplified_labels,
            "tooltipsEnabled": preferences.tooltips_enabled,
            "language": preferences.language.clone(),
            "routePrimaryLabel": preferences.route_primary_label.clone(),
            "routeSecondaryLabel": preferences.route_secondary_label.clone(),
            "selectedPrimaryInterfaceId": preferences.selected_primary_interface_id.clone(),
            "selectedPrimaryInterfaceName": preferences.selected_primary_interface_name.clone(),
            "primaryRoleUserConfirmed": preferences.primary_role_user_confirmed,
            "selectedSecondaryInterfaceId": preferences.selected_secondary_interface_id.clone(),
            "selectedSecondaryInterfaceName": preferences.selected_secondary_interface_name.clone(),
            "secondaryRoleUserConfirmed": preferences.secondary_role_user_confirmed,
            "routeBehaviorMode": preferences.route_behavior_mode.slug(),
            // The UI mirror of the service per-SID
            // `block-secondary-when-unavailable` flag, so the Routing
            // settings checkbox renders the saved choice. The
            // authoritative value is written through `route.policy.update`.
            "showBluetoothAdapters": preferences.show_bluetooth_adapters,
            // Display toggle for the security-audit viewing tab in the Logs
            // area (default off). Device-local; the audit trail is recorded
            // regardless — this only gates whether the read-only tab is shown.
            "showAuditTab": preferences.show_audit_tab,
            // Idle delay before a settings panel commits its own drafts.
            "settingsAutosaveSecs": preferences.settings_autosave_secs,
            "adminAutoRevokeDisabled": preferences.admin_auto_revoke_disabled,
            "adminAutoRevokeMinutes": preferences.admin_auto_revoke_minutes,
            // Experimental opt-in that reveals the legacy kill-switch mode A
            // (reactive) option in routing settings (default off). Device-local.
            "allowModeAKillswitch": preferences.allow_mode_a_killswitch,
            // Experimental opt-in that reveals the "pre-flight, then
            // all-or-nothing" apply-failure policy option in routing settings
            // (default off). Device-local.
            // Display toggle for the "remembered but absent" ghost
            // rows in the Interfaces section (default on). Device-local.
            "showRememberedAdapters": preferences.show_remembered_adapters,
            "autoConfirmAdapterIdChange": preferences.auto_confirm_adapter_id_change,
            // Opt-out for the "leak protection is blocking unknown
            // traffic" banner (default on). Device-local display preference.
            "warnKillSwitchBlockAll": preferences.warn_kill_switch_block_all,
            // Persisted acknowledgement of the block-all banner (default off).
            // Device-local display state; cleared by the GUI when the posture disarms.
            "killSwitchBannerAcknowledged": preferences.kill_switch_banner_acknowledged,
            // Persisted acknowledgement of the "additional adapter not found"
            // banner (default off). Device-local display state; cleared by the
            // GUI when the secondary adapter resolves again.
            "missingSecondaryBannerAcknowledged": preferences.missing_secondary_banner_acknowledged,
            // Selected traffic-statistics period slug ("today" / "session").
            // Device-local UI display state; the GUI normalizes unexpected values.
            "trafficStatsPeriod": preferences.traffic_stats_period.clone(),
            // Remembered byte unit for the traffic CSV export.
            "trafficExportUnit": preferences.traffic_export_unit.clone(),
            // Remembered support-archive privacy tier ("standard" / "diagnostics")
            // and the "current session only" log scope. Both export surfaces read
            // these, so the choice survives a restart instead of resetting.
            "diagnosticsArchiveRedactionLevel": preferences.diagnostics_archive_redaction_level.clone(),
            "diagnosticsArchiveSessionOnly": preferences.diagnostics_archive_session_only,
            // Cap in MiB on the raw service logs attached to a support
            // archive; `0` = unlimited (the default).
            "archiveLogBudgetMib": preferences.archive_log_budget_mib,
            // Persisted dismiss signature for the "app rules aren't active
            // yet" notification (sorted set, `|`-joined).
            "unenforcedAppsAckSig": preferences.unenforced_apps_ack_signature.clone(),
            // Overlap pairs the user asked the rules screen to stop offering
            // for cleanup (`|`-joined).
            "rulesOverlapKeepSig": preferences.rules_overlap_keep_signature.clone(),
            "routeOverlapsConfirmedSig": preferences.route_overlaps_confirmed_signature.clone(),
            // Device-local record of the executable the user pointed out as
            // their VPN in the onboarding dialog.
            "confirmedVpnExePath": preferences.confirmed_vpn_exe_path.clone(),
            // Full semicolon-joined set of confirmed VPN executables.
            // `confirmedVpnExePath` mirrors the first entry.
            "confirmedVpnExePaths": preferences.confirmed_vpn_exe_paths.clone(),
            "lastOpenedSection": preferences.last_opened_section.slug(),
            // Device-local mirror of the per-SID policy
            // toggles, so the GUI can re-seed them after a service-DB wipe. The
            // authoritative values are written through `route.policy.update`.
            "routeIncludeSubdomains": preferences.route_include_subdomains,
            "routeSharedIpPolicy": preferences.route_shared_ip_policy.clone(),
            "routeKillSwitchBlockAll": preferences.route_kill_switch_block_all,
            "routeKillSwitchFailClosed": preferences.route_kill_switch_fail_closed,
            "routeKillSwitchProtocols": preferences.route_kill_switch_protocols,
            // The MASTER kill-switch toggle and the DNS-over-primary opt-in
            // must round-trip through this context emit and the incoming
            // QtPreferencesPayload parse — otherwise they can only ride the
            // service state DB, and a clean service-DB wipe silently loses
            // them. Emitting (and parsing below) makes the offline re-seed
            // after a wipe work.
            "routeKillSwitchEnabled": preferences.route_kill_switch_enabled,
            "routeAllowDnsOverPrimary": preferences.route_allow_dns_over_primary,
            // Mode-A coverage strategy + hosts-bypass mirrors (the same
            // emit/parse/apply triple as every other per-SID policy mirror).
            "routeModeACoverageStrategy": preferences.route_mode_a_coverage_strategy.clone(),
            "routeResolveHostsBypass": preferences.route_resolve_hosts_bypass,
            "routeEnforcementMode": preferences.route_enforcement_mode.clone(),
            // Device-local mirror of the GLOBAL "secondary tunnel liveness
            // window" (seconds); `0` = disabled.
            "routeLivenessWindowSecs": preferences.route_liveness_window_secs,
            // Pending offline routing intents (opaque compact-JSON object
            // as a STRING; empty = none).
            "routePendingOfflineJson": preferences.route_pending_offline_json.clone(),
            // Diagnostics cache-viewer persisted column widths (opaque compact-
            // JSON object as a STRING; empty = defaults).
            "cacheTableColumnWidths": preferences.cache_table_column_widths.clone(),
            // Last-known values of the service-owned settings (opaque compact-
            // JSON object as a STRING; empty = nothing mirrored yet). Lets the
            // panels show the user's real values while the service is stopped.
            "serviceBackedMirrorJson": preferences.service_backed_mirror_json.clone(),
            // What the user asked the service-owned settings to be (opaque
            // compact-JSON object as a STRING; empty = never touched). Replayed
            // to the service on connect so a wiped service DB cannot overwrite
            // the user's choices with its defaults.
            "serviceIntentJson": preferences.service_intent_json.clone(),
            // File-source state. Emitted as JSON null (not omitted) so
            // QML always sees the keys; `Option::None` serialises as
            // `null` via serde_json, which QML reads as the JS `null`
            // literal.
            "lastSavedPathPrimary": preferences.last_saved_path_primary.clone(),
            "lastSavedPathSecondary": preferences.last_saved_path_secondary.clone(),
            // Display-only "Source:" paths — unlike lastSavedPath* these may
            // point inside the read-only bundled presets tree (they are never
            // used as a write target).
            "lastLoadedPathPrimary": preferences.last_loaded_path_primary.clone(),
            "lastLoadedPathSecondary": preferences.last_loaded_path_secondary.clone(),
            "autoOpenOnLaunchPathPrimary": preferences.auto_open_on_launch_path_primary.clone(),
            "autoOpenOnLaunchPathSecondary": preferences.auto_open_on_launch_path_secondary.clone(),
            // UAC decline state, surfaced so the FirstLaunchInstallDialog
            // and connection-banner action can downgrade to passive when
            // re-prompting is annoying.
            "serviceInstallUacDeclinedAtEpoch":
                preferences.service_install_uac_declined_at_epoch,
            "serviceInstallUacDeclinedCount":
                preferences.service_install_uac_declined_count,
            "serviceInstallPromptSuppressed":
                preferences.service_install_prompt_suppressed,
            "autoLoadRulesOnLaunch": preferences.auto_load_rules_on_launch,
            "exportIncludeComments": preferences.export_include_comments,
            "importOnlyActive": preferences.import_only_active,
            "compatBannerMode": preferences.compat_banner_mode.clone(),
            "updatePageUrl": preferences.update_page_url.clone(),
            "updateCheckEnabled": preferences.update_check_enabled,
            "updateCheckIntervalDays": preferences.update_check_interval_days,
            "dismissedUpdateVersion": preferences.dismissed_update_version.clone(),
            "showBundledPresets": preferences.show_bundled_presets,
            // Folder the user keeps their own rule sets in. Empty means the
            // quick-load dropdown lists the shipped sets.
            "userPresetsDir": preferences.user_presets_dir.clone(),
            // The rule set the quick-load dropdown reopens on, `<source>:<label>`.
            // Empty = no choice made yet (the only state where the shipped-set
            // list may pick one by system locale).
            "selectedPresetSet": preferences.selected_preset_set.clone(),
            // "Do not ask again" for the warning about saving a set into
            // the folder that ships with the app.
            "allowSavingIntoBundledPresets": preferences.allow_saving_into_bundled_presets,
            // The one-time "keep your sets here?" offer was dismissed; it
            // never returns.
            "rulesFolderSuggestionDismissed": preferences.rules_folder_suggestion_dismissed,
            // File<->service merge conflict-resolution policy.
            "mergeConflictPolicy": preferences.merge_conflict_policy.clone(),
            // Persisted per-adapter ack for the split-routing banner.
            "secondarySplitAckAdapterName":
                preferences.secondary_split_ack_adapter_name.clone(),
        },
        "theme": {
            "selectedMode": resolved_theme.selected_mode.slug(),
            "effectiveMode": resolved_theme.effective_mode.slug(),
            "systemMode": resolved_theme.system_mode.slug(),
            "systemModeDetected": resolved_theme.system_mode_detected,
        },
        "localeCatalog": locale_catalog.clone(),
        "localeDiagnostics": locale_diagnostics,
        "availableLanguages": locale_descriptors.iter().map(|descriptor| json!({
            "id": descriptor.id,
            "label": descriptor.label,
            "nativeLabel": descriptor.native_label,
        })).collect::<Vec<_>>(),
        "firstRun": {
            "completionNotice": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "first-run.notice.completion",
                first_run.completion_notice,
            ),
        },
        "interfaces": {
            "dataSource": interfaces_snapshot.data_source.title(),
            "selectedBehaviorMode": interfaces_snapshot.selected_behavior_mode.slug(),
            // QML labels each mode itself from `interfaces.mode.<id>`.
            "supportedBehaviorModes": interfaces_snapshot.supported_behavior_modes.iter().map(|mode| json!({
                "id": mode.slug(),
            })).collect::<Vec<_>>(),
            "rows": interface_rows_json,
        },
        "rules": {
            "supportedRuleTypes": supported_rule_types,
            "rows": rules_rows_json,
        },
        "diagnostics": {
            "overallHealthy": diagnostics_status.overall_healthy,
            "stale": diagnostics_status.stale,
            "origin": diagnostics_status.origin.as_str(),
            "serviceHealth": {
                "state": diagnostics_status.service_health.state,
                "activeRevisionId": diagnostics_status.service_health.active_revision_id,
                "pendingChanges": diagnostics_status.service_health.pending_changes,
                // A fact about THIS boot, so the cold-start snapshot carries it
                // for the whole session — there is nothing for a live poll to
                // refresh.
                "startRelativeToSignIn":
                    diagnostics_status.service_health.start_relative_to_sign_in,
                "startSignInGapMs": diagnostics_status.service_health.start_sign_in_gap_ms,
            },
            "securityStatus": {
                "auditChainOk": diagnostics_status.security_status.audit_chain_ok,
                "activeAlertCount": diagnostics_status.security_status.active_alert_count,
                "auditWriteHealthy": diagnostics_status.security_status.audit_write_healthy,
            },
            "alertsStale": active_alerts.stale,
            // The service answered but could not read its alert store: the
            // list says nothing, which is not "no alerts".
            "alertsUnreadable": !diagnostics_status.stale
                && !diagnostics_status.security_status.alerts_readable,
            "activeAlerts": active_alerts.alerts.iter().map(|alert| json!({
                "alertId": alert.alert_id,
                "kind": alert.kind,
                "state": alert.state,
                "createdAt": alert.created_at,
                "updatedAt": alert.updated_at,
                "reasonCode": alert.reason_code,
                "raisedFile": alert.raised_file,
                "requiresAction": alert.requires_action,
            })).collect::<Vec<_>>(),
            "cacheHealth": {
                "entryCount": diagnostics_status.cache_health.entry_count,
                "healthy": diagnostics_status.cache_health.healthy,
            },
            "logHealth": {
                "dirWritable": diagnostics_status.log_health.dir_writable,
                "totalSizeBytes": diagnostics_status.log_health.total_size_bytes,
                "auditSizeBytes": diagnostics_status.log_health.audit_size_bytes,
                "fileCount": diagnostics_status.log_health.file_count,
                "droppedCount": diagnostics_status.log_health.dropped_count,
                "lastCleanupAt": diagnostics_status.log_health.last_cleanup_at,
            },
            // Cold-start emit is null; the GUI fetches a real explain
            // sample on demand via `rpcExplainGetBySample` and renders it
            // in the Diagnostics section. The cold JSON slot stays `null`
            // because explain output is per-decision, not a bootstrap
            // snapshot.
            "explainSample": null,
        },
        "logs": {
            "entries": logs_page.items.iter().map(|entry| json!({
                "eventId": entry.event_id,
                "createdAt": entry.created_at,
                "level": entry.level,
                "category": entry.category,
                "kind": entry.kind,
                "messageKey": entry.message_key,
                "message": entry.message,
                "args": entry.args,
                "hasPayload": entry.has_payload,
                "correlationSummary": entry.correlation_summary,
            })).collect::<Vec<_>>(),
            "nextPageToken": logs_page.next_cursor.as_ref().map(|c| c.as_str().to_string()),
            "totalKnownCount": logs_page.total_count,
            "stale": logs_page.stale,
        },
        "audit": {
            "entries": audit_page.items.iter().map(|entry| json!({
                "eventId": entry.event_id,
                "seq": entry.seq,
                "kind": entry.kind,
                "createdAt": entry.created_at,
                "result": entry.result,
                "reasonCode": entry.reason_code,
                "revisionId": entry.revision_id,
                "hasPayloadSummary": entry.has_payload_summary,
            })).collect::<Vec<_>>(),
            "nextPageToken": audit_page.next_cursor.as_ref().map(|c| c.as_str().to_string()),
            "totalKnownCount": audit_page.total_count,
            "stale": audit_page.stale,
        },
        "about": {
            "productName": about.product_name,
            "version": about.version,
            "license": about.license,
            "buildProfile": about.build_profile,
            "toolchain": about.rust_toolchain,
            "projectUrl": shell.about.project_url,
            "buildChannel": shell.about.build_channel,
            "author": shell.about.author,
            "authorEmail": shell.about.author_email,
            "resetScriptPath": reset_script_path,
            "resetScriptCommand": reset_script_command,
            "logsFolderUrl": logs_folder_url,
            "licenseText": license_text,
        },
        // Scheduled GitHub release check result (from the launcher-maintained
        // cache; see `crate::update_check`). `null` when up to date / never
        // checked / cache unreadable / the check is switched off — the QML
        // notification only fires on a concrete newer version.
        "updateCheck": preferences
            .update_check_enabled
            .then(|| crate::update_check::update_available(env!("CARGO_PKG_VERSION")))
            .flatten()
            .map(|(version, url)| json!({ "latestVersion": version, "url": url })),
        // The frequency dropdown offers exactly what the preference accepts.
        "updateCheckIntervalChoices":
            nrr_ui_support::ui_preferences::UPDATE_CHECK_INTERVAL_DAYS_CHOICES,
        "eula": {
            // Back-compat: `text` = the text for the CURRENT app language.
            "text": eula_text,
            // Both languages ship in the context so the agreement window
            // can switch instantly (no bridge round-trip); `defaultLanguage`
            // mirrors the resolved app language (ru → ru, anything else →
            // en) so the window opens in the right one.
            "textRu": load_eula_text("ru"),
            "textEn": load_eula_text("en"),
            "defaultLanguage": if preferences.language.starts_with("ru") { "ru" } else { "en" },
            "currentVersion": nrr_shared::eula::CURRENT_EULA_VERSION,
            "acceptedVersion": preferences.accepted_eula_version,
        },
    });

    // Compact, not pretty: exactly one reader — the Qt host's JSON parser —
    // and the indentation was roughly a third of a ~600 KB file written on
    // every launch.
    let payload =
        serde_json::to_string(&context).map_err(|error| format!("JSON error: {error}"))?;
    // Exclusive, owner-only creation rather than `fs::write`: the file carries
    // the user's settings, and on Unix the coordination directory can sit in a
    // shared `/tmp`, where a planted symlink would redirect the write.
    let mut file = nrr_platform_api::paths::create_private_file(file_path)
        .map_err(|error| format!("Failed to create Qt context file: {error}"))?;
    std::io::Write::write_all(&mut file, payload.as_bytes())
        .map_err(|error| format!("Failed to write Qt context file: {error}"))?;
    Ok(())
}

pub fn apply_qt_preferences_payload(
    current: UiPreferences,
    serialized_payload: &str,
) -> Result<UiPreferences, String> {
    let normalized_payload = serialized_payload.trim_start_matches('\u{feff}').trim();
    let payload: QtPreferencesPayload = serde_json::from_str(normalized_payload)
        .map_err(|error| format!("Failed to parse Qt preferences payload: {error}"))?;
    Ok(payload.apply_over(current))
}

/// `file://` URL for a local path, percent-encoded: a reader parses it with a
/// URL parser, which would cut `C:\Users\C#dev` at `#` and decode `%XX`.
pub fn path_to_file_url(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let mut url = String::with_capacity(normalized.len() + 8);
    url.push_str(if normalized.starts_with('/') {
        "file://"
    } else {
        "file:///"
    });
    for byte in normalized.bytes() {
        // RFC 3986 `pchar` plus the separator; everything else is escaped.
        if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&byte) {
            url.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            url.push('%');
            url.push(char::from(HEX[usize::from(byte >> 4)]));
            url.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
    url
}

/// Every field is an `Option`: a missing key keeps the stored value, where a
/// serde default would reset it. Fields whose stored value is itself optional
/// take [`present`], so an explicit `null` still clears them.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QtPreferencesPayload {
    #[serde(default)]
    launch_window_on_startup: Option<bool>,
    #[serde(default)]
    minimize_to_tray_instead_of_close: Option<bool>,
    #[serde(default)]
    show_notifications: Option<bool>,
    #[serde(default)]
    notify_suggestion_changes: Option<bool>,
    #[serde(default)]
    notify_block_notices: Option<bool>,
    #[serde(default)]
    notify_rule_duplicates: Option<bool>,
    #[serde(default)]
    hide_block_notice_addresses: Option<bool>,
    #[serde(default)]
    tray_notice_opacity_percent: Option<u16>,
    #[serde(default)]
    reopen_last_section_on_startup: Option<bool>,
    #[serde(default)]
    first_run_completed: Option<bool>,
    #[serde(default)]
    accepted_eula_version: Option<u32>,
    #[serde(default)]
    theme_mode: Option<String>,
    #[serde(default)]
    accessibility_high_contrast: Option<bool>,
    #[serde(default)]
    font_scale_percent: Option<u16>,
    #[serde(default)]
    system_font: Option<String>,
    #[serde(default)]
    enhanced_focus: Option<bool>,
    #[serde(default)]
    simplified_labels: Option<bool>,
    #[serde(default)]
    tooltips_enabled: Option<bool>,
    #[serde(default)]
    language: Option<String>,
    #[serde(default)]
    route_primary_label: Option<String>,
    #[serde(default)]
    route_secondary_label: Option<String>,
    #[serde(default)]
    selected_primary_interface_id: Option<String>,
    #[serde(default)]
    selected_primary_interface_name: Option<String>,
    #[serde(default)]
    primary_role_user_confirmed: Option<bool>,
    #[serde(default)]
    selected_secondary_interface_id: Option<String>,
    #[serde(default)]
    selected_secondary_interface_name: Option<String>,
    #[serde(default)]
    secondary_role_user_confirmed: Option<bool>,
    #[serde(default)]
    route_behavior_mode: Option<String>,
    #[serde(default)]
    show_bluetooth_adapters: Option<bool>,
    #[serde(default)]
    show_audit_tab: Option<bool>,
    // Idle delay before a settings panel commits its drafts on its own.
    #[serde(default)]
    settings_autosave_secs: Option<u32>,
    #[serde(default)]
    admin_auto_revoke_disabled: Option<bool>,
    // Idle minutes before the elevated broker session is retired.
    #[serde(default)]
    admin_auto_revoke_minutes: Option<u32>,
    #[serde(default)]
    allow_mode_a_killswitch: Option<bool>,
    // Reveals the DNS/fake-IP tuning toggles in routing settings.
    #[serde(default)]
    routing_detailed_mode: Option<bool>,
    #[serde(default)]
    show_virtual_machines_section: Option<bool>,
    #[serde(default)]
    app_groups_offer_dismissed: Option<bool>,
    #[serde(default)]
    show_remembered_adapters: Option<bool>,
    #[serde(default)]
    auto_confirm_adapter_id_change: Option<bool>,
    #[serde(default)]
    warn_kill_switch_block_all: Option<bool>,
    #[serde(default)]
    kill_switch_banner_acknowledged: Option<bool>,
    #[serde(default)]
    missing_secondary_banner_acknowledged: Option<bool>,
    #[serde(default)]
    traffic_stats_period: Option<String>,
    #[serde(default)]
    traffic_export_unit: Option<String>,
    #[serde(default)]
    diagnostics_archive_redaction_level: Option<String>,
    #[serde(default)]
    diagnostics_archive_session_only: Option<bool>,
    // Raw-log attachment cap in MiB; `0` = unlimited.
    #[serde(default)]
    archive_log_budget_mib: Option<u32>,
    // The signatures, paths and blobs below clear on an explicit empty string.
    #[serde(default)]
    unenforced_apps_ack_sig: Option<String>,
    #[serde(default)]
    rules_overlap_keep_sig: Option<String>,
    #[serde(default)]
    route_overlaps_confirmed_sig: Option<String>,
    #[serde(default)]
    confirmed_vpn_exe_path: Option<String>,
    #[serde(default)]
    confirmed_vpn_exe_paths: Option<String>,
    // Device-local mirrors of the per-SID policy settings, so they survive a
    // service-DB wipe.
    #[serde(default)]
    route_include_subdomains: Option<bool>,
    #[serde(default)]
    route_shared_ip_policy: Option<String>,
    #[serde(default)]
    route_kill_switch_block_all: Option<bool>,
    #[serde(default)]
    route_kill_switch_fail_closed: Option<bool>,
    #[serde(default)]
    route_kill_switch_protocols: Option<u32>,
    #[serde(default)]
    route_kill_switch_enabled: Option<bool>,
    #[serde(default)]
    route_allow_dns_over_primary: Option<bool>,
    #[serde(default)]
    route_mode_a_coverage_strategy: Option<String>,
    #[serde(default)]
    route_resolve_hosts_bypass: Option<bool>,
    #[serde(default)]
    route_enforcement_mode: Option<String>,
    // Secondary tunnel liveness window in seconds; `0` = disabled.
    #[serde(default)]
    route_liveness_window_secs: Option<u32>,
    // Opaque compact-JSON objects carried as strings.
    #[serde(default)]
    route_pending_offline_json: Option<String>,
    #[serde(default)]
    cache_table_column_widths: Option<String>,
    #[serde(default)]
    service_backed_mirror_json: Option<String>,
    #[serde(default)]
    service_intent_json: Option<String>,
    #[serde(default)]
    last_opened_section: Option<String>,

    // File-source state.
    #[serde(default, deserialize_with = "present")]
    last_saved_path_primary: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    last_saved_path_secondary: Option<Option<String>>,
    // Display-only "Source:" paths (may point inside the bundled presets
    // tree — read-only source, never a save target).
    #[serde(default, deserialize_with = "present")]
    last_loaded_path_primary: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    last_loaded_path_secondary: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    auto_open_on_launch_path_primary: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    auto_open_on_launch_path_secondary: Option<Option<String>>,

    #[serde(default, deserialize_with = "present")]
    service_install_uac_declined_at_epoch: Option<Option<i64>>,
    #[serde(default)]
    service_install_uac_declined_count: Option<u32>,
    /// "Stop offering to install the service".
    #[serde(default)]
    service_install_prompt_suppressed: Option<bool>,

    #[serde(default)]
    auto_load_rules_on_launch: Option<bool>,
    #[serde(default)]
    export_include_comments: Option<bool>,
    #[serde(default)]
    import_only_active: Option<bool>,
    #[serde(default)]
    compat_banner_mode: Option<String>,
    #[serde(default)]
    update_page_url: Option<String>,
    #[serde(default)]
    update_check_enabled: Option<bool>,
    #[serde(default)]
    update_check_interval_days: Option<u32>,
    #[serde(default)]
    dismissed_update_version: Option<String>,
    #[serde(default)]
    show_bundled_presets: Option<bool>,
    // Folder the user keeps their own rule sets in; an explicit empty string
    // is "back to the shipped sets".
    #[serde(default)]
    user_presets_dir: Option<String>,
    // The remembered quick-load selection, `<source>:<label>`.
    #[serde(default)]
    selected_preset_set: Option<String>,
    // Acknowledgement of the "this folder is overwritten by an update" warning.
    #[serde(default)]
    allow_saving_into_bundled_presets: Option<bool>,
    #[serde(default)]
    rules_folder_suggestion_dismissed: Option<bool>,
    #[serde(default)]
    merge_conflict_policy: Option<String>,
    // Per-adapter ack for the split-routing banner.
    #[serde(default)]
    secondary_split_ack_adapter_name: Option<String>,
}

/// A key that is present, `null` included: `Some(None)` clears a stored
/// optional value, where an absent key (`None`, via `default`) keeps it.
fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

mod preferences_payload;
// ── Backend status payload helper ─────────────────────────────────────────

/// Maps a [`BackendConnectionStatus`] to the kebab-case JSON shape
/// consumed by `Main.qml`'s connection banner. Shape:
///
/// - `kind = "connected" | "connecting" | "disconnected" | "service-stopped" | "service-not-installed" | "protocol-mismatch" | "refused"`
/// - `lastError` is present when `kind == "disconnected"`
/// - `serverVersion` / `clientVersion` are present when `kind == "protocol-mismatch"`
fn backend_connection_status_to_payload(status: &BackendConnectionStatus) -> serde_json::Value {
    match status {
        BackendConnectionStatus::Connected => json!({"kind": "connected"}),
        BackendConnectionStatus::Connecting => json!({"kind": "connecting"}),
        BackendConnectionStatus::Disconnected { last_error } => {
            json!({"kind": "disconnected", "lastError": last_error})
        }
        BackendConnectionStatus::ServiceStopped => json!({"kind": "service-stopped"}),
        BackendConnectionStatus::ServiceNotInstalled => {
            json!({"kind": "service-not-installed"})
        }
        BackendConnectionStatus::ProtocolMismatch {
            server_version,
            client_version,
        } => json!({
            "kind": "protocol-mismatch",
            "serverVersion": server_version,
            "clientVersion": client_version,
        }),
        BackendConnectionStatus::Refused { reason } => {
            json!({"kind": "refused", "lastError": reason})
        }
    }
}

/// Is the facade behind this launch a REAL service connection, or a
/// mock/preview stand-in?
///
/// `BackendConnectionStatus` alone cannot answer that: an explicit mock or
/// preview-local launch reports `Connected` while nothing it returns ever
/// reaches the service. The GUI needs the distinction because a routing change
/// made against a stand-in has to be PARKED (offered again once a real service
/// is reachable), exactly like a change made while the service was stopped —
/// otherwise the toggle looks applied and is silently lost.
///
/// The flag describes the COLD-START facade only. The Qt host's own IPC client
/// keeps reconnecting independently, so a successful live health read later in
/// the session supersedes this (see `Main.qml`'s `_routingBackendConnected`).
fn backend_provider_is_service_backed(kind: BackendProviderKind) -> bool {
    match kind {
        BackendProviderKind::Mock | BackendProviderKind::PreviewLocal => false,
        BackendProviderKind::IpcConnected
        | BackendProviderKind::IpcDisconnected
        | BackendProviderKind::IpcServiceNotInstalled
        | BackendProviderKind::IpcProtocolMismatch => true,
    }
}

#[cfg(test)]
mod reset_script_tests;

#[cfg(test)]
mod file_url_tests;

#[cfg(test)]
mod backend_provider_tests;

#[cfg(test)]
mod backend_status_payload_tests;
