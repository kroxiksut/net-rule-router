use nrr_application::backend_facade::network_interfaces::RouteSelectionRequest;
use nrr_application::backend_facade::rules::RulesScreenRequest;
use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, BackendProviderKind,
};
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
    let manifest_candidate =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets/icons/app/icon-256.png");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    let cwd_candidate = env::current_dir()
        .ok()?
        .join("assets/icons/app/icon-256.png");
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    None
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

    if let Ok(exe) = env::current_exe() {
        let mut dir = exe.parent();
        for _ in 0..6 {
            let Some(d) = dir else { break };
            let candidate = d.join(RESET_SCRIPT);
            if candidate.exists() {
                return Some(candidate);
            }
            dir = d.parent();
        }
    }

    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../")
        .join(RESET_SCRIPT);
    if manifest_candidate.exists() {
        return manifest_candidate.canonicalize().ok();
    }

    let cwd_candidate = env::current_dir().ok()?.join(RESET_SCRIPT);
    cwd_candidate.exists().then_some(cwd_candidate)
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

fn default_archive_folder_hint() -> String {
    if let Some(profile) = env::var_os("USERPROFILE") {
        let mut path = PathBuf::from(profile);
        path.push("Documents");
        path.push("NetRuleRouter");
        path.push("diagnostic-archives");
        return path.to_string_lossy().into_owned();
    }
    r"%USERPROFILE%\Documents\NetRuleRouter\diagnostic-archives".to_string()
}

fn resolve_logs_directory() -> Option<PathBuf> {
    // The service's own operational-log directory, asked of the layer that
    // declares it (`%ProgramData%\<product>\logs` on Windows,
    // `/var/log/<product>` on Linux). The user-facing "Open logs folder"
    // action MUST land there or the user sees an empty directory.
    let leaf = nrr_platform_api::paths::product_dir_leaf();
    let mut candidates = Vec::new();
    candidates.extend(nrr_platform_api::paths::production_logs_dir());
    // Fallbacks for environments where the service isn't installed
    // (dev/test). We do NOT create the production one — the service owns
    // that path and the GUI shouldn't be racing the ACL setup. Per-user
    // candidates remain as last resort.
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(PathBuf::from(local_app_data).join(leaf).join("logs"));
    }
    if let Some(app_data) = env::var_os("APPDATA") {
        candidates.push(PathBuf::from(app_data).join(leaf).join("logs"));
    }
    candidates.push(env::temp_dir().join(leaf).join("logs"));

    // Existing path wins — and only if THIS process can actually list it.
    // The service's log directory is closed to ordinary users, so offering to
    // open a folder the user cannot read would send them to an empty window
    // with no explanation; the window shows "unavailable" instead, and the
    // diagnostics archive is the path that works for everyone.
    if let Some(existing) = candidates
        .iter()
        .find(|p| p.is_dir() && fs::read_dir(p).is_ok())
    {
        return Some(existing.clone());
    }
    candidates
        .into_iter()
        .find(|candidate| fs::create_dir_all(candidate).is_ok())
}

fn load_license_text() -> String {
    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../LICENSE");
    if let Ok(content) = fs::read_to_string(&manifest_candidate) {
        return content;
    }

    if let Ok(current_dir) = env::current_dir() {
        let cwd_candidate = current_dir.join("LICENSE");
        if let Ok(content) = fs::read_to_string(cwd_candidate) {
            return content;
        }
    }

    "License text could not be loaded.".to_string()
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

/// Candidate `docs/legal` directories to probe for the EULA markdown at
/// runtime: the source tree (dev / build-tree runs) and a `docs/legal` beside
/// the current working directory (a deployed layout that ships the docs).
fn eula_doc_dirs() -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/legal"));
    if let Ok(current_dir) = env::current_dir() {
        dirs.push(current_dir.join("docs/legal"));
    }
    dirs
}

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
    for dir in eula_doc_dirs() {
        if let Ok(content) = fs::read_to_string(dir.join(name)) {
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
    let base_route_selection_request = RouteSelectionRequest {
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
        include_bluetooth_adapters: preferences.show_bluetooth_adapters,
        behavior_mode: preferences.route_behavior_mode,
    };
    let interfaces_request = RouteSelectionRequest {
        include_bluetooth_adapters: true,
        ..base_route_selection_request.clone()
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
    let diagnostics_status = if budget_left(&cold_start_started) {
        backend.diagnostics_status_snapshot()
    } else {
        budget_spent = true;
        nrr_application::mock_backend::diagnostics::preview_diagnostics_status()
    };
    timed("diagnostics", t);
    let t = std::time::Instant::now();
    let active_alerts = if budget_left(&cold_start_started) {
        backend.list_security_alerts(None)
    } else {
        budget_spent = true;
        nrr_application::mock_backend::diagnostics::preview_active_security_alerts()
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
    let t = std::time::Instant::now();
    let security_snapshot = if budget_left(&cold_start_started) {
        backend.status_snapshot()
    } else {
        budget_spent = true;
        nrr_application::mock_backend::security_status::security_status_preview_snapshot()
    };
    timed("status", t);
    let total: u128 = cold_start_timings.iter().map(|(_, ms)| ms).sum();
    if budget_spent {
        println!(
            "NRR_LAUNCHER[cold-start] budget of {}ms spent — the rest is local,              the window opens now and the GUI refreshes from the service",
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
    let logs_folder_url = resolve_logs_directory()
        .as_ref()
        .map(|path| path_to_file_url(path));
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
    let interfaces_role_assignment_advisory = json!({
        "manualConfirmationRequired": interfaces_snapshot
            .role_assignment_advisory
            .manual_confirmation_required,
        "userChoicePriorityNote": interfaces_snapshot
            .role_assignment_advisory
            .user_choice_priority_note,
        "conflictWarning": interfaces_snapshot
            .role_assignment_advisory
            .conflict_warning,
        "warnings": interfaces_snapshot.role_assignment_advisory.warnings,
    });
    let interface_rows_json = interfaces_snapshot
        .rows
        .iter()
        .map(|row| {
            json!({
                "persistentId": row.persistent_id,
                "name": row.windows_name,
                "description": row.interface_description,
                "type": row.interface_type,
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
                    "externalProbeAttempted": row.observed_facts.external_probe_attempted,
                    "externalProbeNote": row.observed_facts.external_probe_note,
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
                    "summary": row.recommendation.summary,
                    "keySignals": row.recommendation.key_signals,
                    "excludedAlternatives": row.recommendation.excluded_alternatives,
                },
            })
        })
        .collect::<Vec<_>>();

    // The Free contract's `FreeRuleType` enum tracks runtime-active matchers
    // (Application, Domain, ExactIp). The Add-Rule dialog also offers `Zone`
    // per docs/en/rules-file-format.md Match value syntax — it is a designed-but-not-yet-
    // runtime-bound type, so we surface it alongside the runtime types as a
    // synthetic entry. The QML dialog uses string ids and reads localized
    // titles via `rules.type.<id>`, so adding "zone" here is non-invasive.
    // Validation status comes from the strict semantic validator in
    // `nrr-domain`: same rules as the QML Add-Rule dialog enforces, so
    // any row imported from a hand-edited file gets the same diagnosis
    // as if the user had typed it. The validator is pure; no I/O. The
    // mock fixture also includes one row with a deliberately malformed
    // IPv4 (`300.1.1.1` from `nrr-mock-backend::rules`) so the red-state
    // GUI rendering is exercised without a real service.
    //
    // Production path: the parser-supplied status now ships over IPC
    // from the service via `RulesListResponse.rows[i].validation_status`
    // (16.4 / 16.11). The in-place revalidation below is retained as
    // a fallback for the preview (mock) mode only.
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

    // The rule-type list is sourced solely from the backend snapshot — do
    // NOT prepend a hardcoded entry. `supported_rule_types` already contains
    // `zone` (both the mock `SUPPORTED_FREE_RULE_TYPES` and production
    // `rule_type_slugs()`), so a hardcoded `zone` seed rendered "Зона"/"Zone"
    // TWICE in the Add-Rule dropdown.
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
        "iconFileUrl": icon_file_url,
        "platformProfile": platform_profile,
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
            "lastFileSyncedRevisionIdPrimary": preferences.last_file_synced_revision_id_primary.clone(),
            "lastFileSyncedRevisionIdSecondary": preferences.last_file_synced_revision_id_secondary.clone(),
            "lastFileSyncedHashPrimary": preferences.last_file_synced_hash_primary.clone(),
            "lastFileSyncedHashSecondary": preferences.last_file_synced_hash_secondary.clone(),
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
            "wizardRequired": first_run.wizard_required,
            "selectedScenario": first_run.selected_scenario.slug(),
            "availableScenarios": first_run.available_scenarios.iter().map(|scenario| json!({
                "id": scenario.slug(),
                "title": resolve_catalog_text(
                    &locale_catalog,
                    &preferences.language,
                    &format!("first-run.scenario.{}", scenario.slug()),
                    scenario.title(),
                ),
            })).collect::<Vec<_>>(),
            "steps": first_run.steps.iter().map(|step| json!({
                "id": resolve_catalog_text(
                    &locale_catalog,
                    &preferences.language,
                    &format!("first-run.step.{}", first_run_step_key(step.id)),
                    step.id.title(),
                ),
                "required": step.required
            })).collect::<Vec<_>>(),
            "startupStates": first_run.startup_states.iter().map(|state| json!({
                "section": state.section.slug(),
                "sectionLabel": resolve_catalog_text(
                    &locale_catalog,
                    &preferences.language,
                    &format!("section.{}", state.section.slug()),
                    state.section.title(),
                ),
                "state": resolve_catalog_text(
                    &locale_catalog,
                    &preferences.language,
                    &format!("first-run.state.{}", startup_state_key(state.state)),
                    state.state.title(),
                ),
                "note": state.note,
            })).collect::<Vec<_>>(),
            "listEditingPreviewNotice": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "first-run.notice.list-editing-preview",
                first_run.list_editing_preview_notice,
            ),
            "completionNotice": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "first-run.notice.completion",
                first_run.completion_notice,
            ),
        },
        "interfaces": {
            "roleExplanation": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "interfaces.role-explanation",
                interfaces_snapshot.role_explanation,
            ),
            "dataSource": interfaces_snapshot.data_source.title(),
            "selectedBehaviorMode": interfaces_snapshot.selected_behavior_mode.slug(),
            "roleAssignmentAdvisory": interfaces_role_assignment_advisory,
            "supportedBehaviorModes": interfaces_snapshot.supported_behavior_modes.iter().map(|mode| json!({
                "id": mode.slug(),
                "label": mode.user_label(),
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
                "fileCount": diagnostics_status.log_health.file_count,
                "droppedCount": diagnostics_status.log_health.dropped_count,
                "lastCleanupAt": diagnostics_status.log_health.last_cleanup_at,
            },
            "diagnosticMode": {
                "active": diagnostics_status.diagnostic_mode.active,
                "expiresAt": diagnostics_status.diagnostic_mode.expires_at,
                "remainingMs": diagnostics_status.diagnostic_mode.remaining_ms,
                "scopeKey": diagnostics_status.diagnostic_mode.scope_key,
            },
            // Cold-start emit is null; the GUI fetches a real explain
            // sample on demand via `rpcExplainGetBySample` /
            // `rpcExplainGetByDecisionId` and renders it in the
            // Diagnostics section. The cold JSON slot stays `null`
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
        "diagnosticsSettings": {
            "retention": {
                "logsMaxAgeDays": 90,
                "logsMaxSizeMb": 50,
                "auditMaxAgeDays": 365,
                "auditMaxSizeMb": 50,
            },
            "storageHealth": {
                "logsSizeBytes": diagnostics_status.log_health.total_size_bytes,
                "auditSizeBytes": diagnostics_status.log_health.audit_size_bytes,
                "logFileCount": diagnostics_status.log_health.file_count,
                "droppedEvents": diagnostics_status.log_health.dropped_count,
                "lastCleanup": diagnostics_status.log_health.last_cleanup_at,
                "dirWritable": diagnostics_status.log_health.dir_writable,
            },
            "diagnosticMode": {
                "active": diagnostics_status.diagnostic_mode.active,
                "selectedTtlMs": 3_600_000_i64,
                "remainingMs": diagnostics_status.diagnostic_mode.remaining_ms,
                "expiresAt": diagnostics_status.diagnostic_mode.expires_at,
                "scopeKey": diagnostics_status.diagnostic_mode.scope_key,
            },
            "auditChain": {
                "verified": diagnostics_status.security_status.audit_chain_ok,
            },
            "activeAlertsCount": diagnostics_status.security_status.active_alert_count,
            "archiveDefaultFolder": default_archive_folder_hint(),
        },
        "security": {
            "activeRevision": security_snapshot.active_revision,
            "pendingChanges": security_snapshot.pending_changes.title(),
            "tamperAlerts": security_snapshot.tamper_alerts.title(),
            "rollbackState": security_snapshot.rollback_state.title(),
            "serviceStatus": security_snapshot.service_status.title(),
            "explainWarnings": security_snapshot.explain_warnings.title(),
        },
        "about": {
            "productName": about.product_name,
            "edition": about.edition,
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
        // Daily GitHub release check result (from the launcher-maintained
        // cache; see `crate::update_check`). `null` when up to date / never
        // checked / cache unreadable — the QML notification only fires on
        // a concrete newer version.
        "updateCheck": crate::update_check::update_available(env!("CARGO_PKG_VERSION"))
            .map(|(version, url)| json!({ "latestVersion": version, "url": url })),
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

fn first_run_step_key(step: nrr_shared::FirstRunStepId) -> &'static str {
    match step {
        nrr_shared::FirstRunStepId::Welcome => "welcome",
        nrr_shared::FirstRunStepId::BasicScenarioSelection => "basic-scenario-selection",
        nrr_shared::FirstRunStepId::RoutesSetup => "routes-setup",
        nrr_shared::FirstRunStepId::RulesSetup => "rules-setup",
        nrr_shared::FirstRunStepId::DiagnosticsPreview => "diagnostics-preview",
        nrr_shared::FirstRunStepId::Finish => "finish",
    }
}

fn startup_state_key(state: nrr_shared::StartupDataState) -> &'static str {
    match state {
        nrr_shared::StartupDataState::Empty => "empty",
        nrr_shared::StartupDataState::SemiEmpty => "semi-empty",
        nrr_shared::StartupDataState::TestDataPreview => "test-data-preview",
    }
}

fn path_to_file_url(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QtPreferencesPayload {
    #[serde(default)]
    launch_window_on_startup: Option<bool>,
    #[serde(default)]
    minimize_to_tray_instead_of_close: Option<bool>,
    #[serde(default)]
    show_notifications: Option<bool>,
    /// Additive: a payload written before the per-kind mute existed leaves the
    /// stripe enabled, which is the pre-existing behaviour.
    #[serde(default = "default_true")]
    notify_suggestion_changes: bool,
    /// Additive: a payload written before this mute existed leaves the
    /// block-notice notification enabled, which is the pre-existing behaviour.
    #[serde(default = "default_true")]
    notify_block_notices: bool,
    /// Additive: a payload written before this notice existed leaves it
    /// enabled — the condition it reports is invisible everywhere else.
    #[serde(default = "default_true")]
    notify_rule_duplicates: bool,
    /// Additive: a payload written before this existed leaves addresses
    /// visible, which is the pre-existing behaviour.
    #[serde(default)]
    hide_block_notice_addresses: bool,
    /// Additive: absent means the opaque default.
    #[serde(default = "default_tray_notice_opacity_percent")]
    tray_notice_opacity_percent: u16,
    #[serde(default)]
    reopen_last_section_on_startup: Option<bool>,
    #[serde(default)]
    first_run_completed: Option<bool>,
    // EULA acceptance version. `#[serde(default)]` (→ 0 = not accepted) keeps
    // the round-trip backward-compatible with QML builds that don't emit the
    // key, matching the safe default (re-prompt the agreement).
    #[serde(default)]
    accepted_eula_version: u32,
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
    selected_primary_interface_id: String,
    #[serde(default)]
    selected_primary_interface_name: Option<String>,
    #[serde(default)]
    primary_role_user_confirmed: bool,
    #[serde(default)]
    selected_secondary_interface_id: String,
    #[serde(default)]
    selected_secondary_interface_name: Option<String>,
    #[serde(default)]
    secondary_role_user_confirmed: bool,
    #[serde(default)]
    route_behavior_mode: Option<String>,
    #[serde(default)]
    show_bluetooth_adapters: bool,
    // Security-audit viewing-tab display toggle. `#[serde(default)]` (→ false)
    // keeps the round-trip backward-compatible with QML builds that don't emit
    // the key and matches the safe default (tab hidden).
    #[serde(default)]
    show_audit_tab: bool,
    // Idle delay before a settings panel commits its drafts on its own.
    // `#[serde(default)]` (→ 0) marks "key absent"; the store substitutes its
    // own default for anything outside the supported range.
    #[serde(default)]
    settings_autosave_secs: u32,
    // Administrator-rights idle auto-revoke opt-out. `#[serde(default)]`
    // (→ false) keeps the secure default (auto-revoke ON) for QML builds that
    // don't emit the key.
    #[serde(default)]
    admin_auto_revoke_disabled: bool,
    // Idle minutes before the elevated broker session is retired. `#[serde
    // (default)]` (→ 0) marks "key absent"; the store keeps its own value for
    // anything outside the supported range.
    #[serde(default)]
    admin_auto_revoke_minutes: u32,
    // Legacy kill-switch mode A opt-in. `#[serde(default)]` (→ false) keeps the
    // round-trip backward-compatible with QML builds that don't emit the key and
    // matches the safe default (mode A hidden from the selector).
    #[serde(default)]
    allow_mode_a_killswitch: bool,
    // Detailed routing mode: reveals the DNS/fake-IP tuning toggles in
    // routing settings. `#[serde(default)]` (→ false) keeps the round-trip
    // backward-compatible with QML builds that don't emit the key and matches
    // the safe default (toggles hidden, built-in defaults apply).
    #[serde(default)]
    routing_detailed_mode: bool,
    // "Remembered but absent" ghost-row display toggle. Default true
    // (via `default_true`) so a QML build that omits the key keeps the ON
    // default rather than silently flipping the toggle off.
    #[serde(default = "default_true")]
    show_remembered_adapters: bool,
    #[serde(default = "default_true")]
    auto_confirm_adapter_id_change: bool,
    // Block-all banner opt-out. `default_true` so a QML build that
    // omits the key keeps the warn-ON default rather than silencing the banner.
    #[serde(default = "default_true")]
    warn_kill_switch_block_all: bool,
    // Block-all banner acknowledgement. `#[serde(default)]` (→ false) keeps the
    // round-trip backward-compatible with QML builds that omit the key and
    // matches the safe default (banner shown).
    #[serde(default)]
    kill_switch_banner_acknowledged: bool,
    // "Additional adapter not found" banner acknowledgement. `#[serde(default)]`
    // (→ false) keeps the round-trip backward-compatible with QML builds that
    // omit the key and matches the safe default (banner shown).
    #[serde(default)]
    missing_secondary_banner_acknowledged: bool,
    // Selected traffic-statistics period slug. `#[serde(default)]` (→ empty
    // string) keeps the round-trip backward-compatible with QML builds that
    // omit the key; the apply-back below keeps the stored value when empty.
    #[serde(default)]
    traffic_stats_period: String,
    // Remembered CSV export unit. Same empty-means-absent contract as the
    // period above; the apply-back only accepts a known slug.
    #[serde(default)]
    traffic_export_unit: String,
    // Remembered support-archive privacy tier. Same empty-means-absent contract
    // as the export unit above; the apply-back only accepts a known slug.
    #[serde(default)]
    diagnostics_archive_redaction_level: String,
    // Remembered "current session only" archive scope. `default_true` so a QML
    // build that omits the key keeps the narrow-scope default rather than
    // silently widening the archive to the full retained history.
    #[serde(default = "default_true")]
    diagnostics_archive_session_only: bool,
    // Raw-log attachment cap in MiB; `0` = unlimited. `Option` so a payload
    // that OMITS the key (older QML build) keeps the stored value instead of
    // resetting a cap the user picked.
    #[serde(default)]
    archive_log_budget_mib: Option<u32>,
    // Notification-dismiss signature. `Option` so a payload that OMITS the
    // key (older QML build) keeps the stored value, while an explicit empty
    // string is an honest "never dismissed" state.
    #[serde(default)]
    unenforced_apps_ack_sig: Option<String>,
    // Overlap pairs kept by the user. `Option` so a payload that OMITS the
    // key keeps the stored value; an explicit empty string clears the list.
    #[serde(default)]
    rules_overlap_keep_sig: Option<String>,
    // Confirmed VPN executable path. `Option` so a payload that OMITS the
    // key (older QML build) keeps the stored value; an explicit empty
    // string is an honest "not set" state.
    #[serde(default)]
    confirmed_vpn_exe_path: Option<String>,
    // Full semicolon-joined set of confirmed VPN executables. `Option` so
    // a payload that OMITS the key (older QML build) keeps the stored
    // value; an explicit empty string is an honest "none".
    #[serde(default)]
    confirmed_vpn_exe_paths: Option<String>,
    // Device-local mirror of the per-SID policy toggles (subdomain
    // coverage, shared-IP policy, aggressive kill-switch), so they survive
    // a service-DB wipe. `#[serde(default)]` keeps them additive.
    // Subdomain coverage defaults ON, so an older QML build that omits the
    // key must read `true`, not serde's bare `false`.
    #[serde(default = "default_true")]
    route_include_subdomains: bool,
    #[serde(default)]
    route_shared_ip_policy: String,
    #[serde(default)]
    route_kill_switch_block_all: bool,
    // Remaining routing/blocking mirrors so ALL aggressive settings survive
    // a service-DB wipe. Explicit default fns keep a QML build that omits
    // the key from silently flipping the safe/default value: fail-closed →
    // true, protocols → all (127), enforcement → reactive.
    #[serde(default = "default_true")]
    route_kill_switch_fail_closed: bool,
    #[serde(default = "default_kill_switch_protocols")]
    route_kill_switch_protocols: u32,
    // The MASTER kill-switch toggle + DNS-over-primary opt-in.
    // `#[serde(default)]` → false (the safe default OFF) keeps a QML build
    // that omits the key backward-compatible.
    #[serde(default)]
    route_kill_switch_enabled: bool,
    // Default flipped to true (see ui_preferences); an older QML build
    // that omits the key reads the new safe-usable default.
    #[serde(default = "default_true")]
    route_allow_dns_over_primary: bool,
    // Mode-A coverage strategy + hosts-bypass mirrors. Explicit default
    // fns so an older QML build that omits the keys reads the intended
    // defaults (fail-closed-unknown / bypass ON), never `""` / `false`.
    #[serde(default = "default_mode_a_coverage_strategy")]
    route_mode_a_coverage_strategy: String,
    #[serde(default = "default_true")]
    route_resolve_hosts_bypass: bool,
    #[serde(default = "default_enforcement_mode")]
    route_enforcement_mode: String,
    // Device-local mirror of the GLOBAL "secondary tunnel liveness window"
    // (seconds). `0` = disabled (safe default); any non-zero value is
    // clamped to `[5, 3600]` in `apply_over`.
    #[serde(default = "default_liveness_window_secs")]
    route_liveness_window_secs: u32,
    // Pending offline routing intents (opaque compact-JSON object as a
    // string; empty = none). `#[serde(default)]` keeps older QML builds
    // additive.
    #[serde(default)]
    route_pending_offline_json: String,
    // Diagnostics cache-viewer persisted column widths (opaque compact-JSON
    // object as a string; empty = defaults). `#[serde(default)]` keeps older
    // QML builds that omit the key additive.
    #[serde(default)]
    cache_table_column_widths: String,
    // Last-known service-owned values mirrored for display while the service is
    // stopped (opaque compact-JSON object as a string; empty = nothing
    // mirrored). `#[serde(default)]` keeps older QML builds additive.
    #[serde(default)]
    service_backed_mirror_json: String,
    // The user's intent for the service-owned settings (opaque compact-JSON
    // object as a string; empty = never touched). `#[serde(default)]` keeps
    // older QML builds additive.
    #[serde(default)]
    service_intent_json: String,
    #[serde(default)]
    last_opened_section: Option<String>,

    // File-source state. Optional: an older QML build may not emit
    // these keys, so #[serde(default)] keeps the round-trip
    // backward-compatible.
    #[serde(default)]
    last_saved_path_primary: Option<String>,
    #[serde(default)]
    last_saved_path_secondary: Option<String>,
    // Display-only "Source:" paths (may point inside the bundled presets
    // tree — read-only source, never a save target).
    #[serde(default)]
    last_loaded_path_primary: Option<String>,
    #[serde(default)]
    last_loaded_path_secondary: Option<String>,
    #[serde(default)]
    auto_open_on_launch_path_primary: Option<String>,
    #[serde(default)]
    auto_open_on_launch_path_secondary: Option<String>,
    #[serde(default)]
    last_file_synced_revision_id_primary: Option<String>,
    #[serde(default)]
    last_file_synced_revision_id_secondary: Option<String>,
    #[serde(default)]
    last_file_synced_hash_primary: Option<String>,
    #[serde(default)]
    last_file_synced_hash_secondary: Option<String>,

    // UAC decline state. An older QML build may not emit these keys;
    // `#[serde(default)]` keeps the round-trip backward compatible.
    #[serde(default)]
    service_install_uac_declined_at_epoch: Option<i64>,
    #[serde(default)]
    service_install_uac_declined_count: u32,
    /// "Stop offering to install the service". Absent from an older QML build
    /// reads as `false` — the offer keeps working, which is the safe default
    /// for the one thing without which nothing is enforced.
    #[serde(default)]
    service_install_prompt_suppressed: bool,

    // The two bools default to `true` (matching `UiPreferences::default`)
    // via explicit default fns so a QML build that omits them never
    // silently flips them off; `compat_banner_mode` defaults to "auto";
    // `update_page_url` to "".
    #[serde(default = "default_true")]
    auto_load_rules_on_launch: bool,
    #[serde(default = "default_true")]
    export_include_comments: bool,
    #[serde(default = "default_true")]
    import_only_active: bool,
    #[serde(default = "default_compat_banner_mode")]
    compat_banner_mode: String,
    #[serde(default)]
    update_page_url: String,
    // Bundled-preset visibility. Defaults to `true` via the explicit
    // default fn so a QML build that omits the key never silently hides
    // the preset row.
    #[serde(default = "default_true")]
    show_bundled_presets: bool,
    // Folder the user keeps their own rule sets in. `Option` so a payload
    // that OMITS the key (older QML build) keeps the configured folder,
    // while an explicit empty string is an honest "back to the shipped sets".
    #[serde(default)]
    user_presets_dir: Option<String>,
    // The remembered quick-load selection, `<source>:<label>`. `Option` for the
    // same reason as the folder above: an omitted key (older QML build) must
    // keep the choice the user already made, while an explicit empty string is
    // an honest "forget it, fall back to the default pick".
    #[serde(default)]
    selected_preset_set: Option<String>,
    // Acknowledgement of the "this folder is overwritten by an update"
    // warning. Plain bool: absent (older QML) reads as `false`, which
    // simply means the warning is shown again — the safe direction.
    #[serde(default)]
    allow_saving_into_bundled_presets: bool,
    // Dismissal of the one-time rule-set-folder offer. Absent reads as
    // `false`, i.e. the offer may still appear: harmless, and the banner
    // itself only shows while no folder is configured.
    #[serde(default)]
    rules_folder_suggestion_dismissed: bool,
    // Merge conflict-resolution policy. Defaults to "union" via the
    // explicit default fn so a QML build that omits the key keeps the
    // safe interactive behaviour (conflicts surfaced for the user to resolve).
    #[serde(default = "default_merge_conflict_policy")]
    merge_conflict_policy: String,
    // Persisted per-adapter ack for the split-routing banner. Wire key
    // `secondarySplitAckAdapterName` (camelCase via the struct's rename_all).
    // `#[serde(default)]` (empty string) keeps the round-trip additive.
    #[serde(default)]
    secondary_split_ack_adapter_name: String,
}

fn default_true() -> bool {
    true
}

fn default_tray_notice_opacity_percent() -> u16 {
    100
}

fn default_compat_banner_mode() -> String {
    String::from("auto")
}

fn default_merge_conflict_policy() -> String {
    String::from("union")
}

fn default_kill_switch_protocols() -> u32 {
    127
}

fn default_enforcement_mode() -> String {
    // Kept in sync with `EnforcementMode::default().as_slug()`.
    String::from("resolver")
}

/// Kept in sync with `ModeACoverageStrategy::default().as_slug()`
/// (permissive default, no catch-all).
fn default_mode_a_coverage_strategy() -> String {
    String::from("per-ip")
}

fn default_liveness_window_secs() -> u32 {
    0
}

impl QtPreferencesPayload {
    // `apply_over` writes the adapter-binding fields back into
    // `UiPreferences`: the app's own store of what the service enforces per
    // SID, and what every panel shows while the service is stopped.
    fn apply_over(self, mut current: UiPreferences) -> UiPreferences {
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
mod reset_script_tests {
    use super::*;

    #[test]
    fn recovery_script_resolves_and_its_command_quotes_the_path() {
        let path = resolve_reset_script_path()
            .expect("the source tree always carries the recovery script");
        let path = path.to_string_lossy().into_owned();
        let command = reset_script_command_line(&path);
        assert!(
            command.contains(&format!("\"{path}\"")),
            "the path must be quoted so a space in it cannot split the command: {command}"
        );
    }
}

#[cfg(test)]
mod backend_provider_tests {
    use super::*;

    #[test]
    fn mock_and_preview_local_are_not_service_backed() {
        assert!(!backend_provider_is_service_backed(
            BackendProviderKind::Mock
        ));
        assert!(!backend_provider_is_service_backed(
            BackendProviderKind::PreviewLocal
        ));
    }

    /// Every IPC variant counts as service-backed, including the degraded ones:
    /// the transport is real and the reconnect worker keeps trying, so the GUI
    /// must fall back to `backendStatus.kind` (which already paints the banner)
    /// rather than treating a transient outage as "no service at all".
    #[test]
    fn every_ipc_variant_is_service_backed() {
        for kind in [
            BackendProviderKind::IpcConnected,
            BackendProviderKind::IpcDisconnected,
            BackendProviderKind::IpcServiceNotInstalled,
            BackendProviderKind::IpcProtocolMismatch,
        ] {
            assert!(backend_provider_is_service_backed(kind), "{kind:?}");
        }
    }

    /// The launcher hands the GUI a `MockBackendFacade` when the IPC probe
    /// fails, so the cold-start snapshot is mock data even on the production
    /// path — and the flag must say so.
    #[test]
    fn ipc_fallback_to_mock_reports_not_service_backed() {
        use nrr_application::backend_facade::MockBackendFacade;
        let facade = MockBackendFacade;
        let backend: &dyn BackendFacade = &facade;
        assert!(!backend_provider_is_service_backed(backend.provider_kind()));
    }
}

#[cfg(test)]
mod backend_status_payload_tests {
    use super::*;

    #[test]
    fn connected_payload_has_kind_only() {
        let payload = backend_connection_status_to_payload(&BackendConnectionStatus::Connected);
        assert_eq!(payload, json!({"kind": "connected"}));
    }

    #[test]
    fn disconnected_payload_carries_last_error() {
        let payload =
            backend_connection_status_to_payload(&BackendConnectionStatus::Disconnected {
                last_error: "pipe broken".into(),
            });
        assert_eq!(
            payload,
            json!({"kind": "disconnected", "lastError": "pipe broken"})
        );
    }

    #[test]
    fn protocol_mismatch_payload_carries_versions() {
        let payload =
            backend_connection_status_to_payload(&BackendConnectionStatus::ProtocolMismatch {
                server_version: 3,
                client_version: 1,
            });
        assert_eq!(
            payload,
            json!({
                "kind": "protocol-mismatch",
                "serverVersion": 3,
                "clientVersion": 1,
            })
        );
    }
}
