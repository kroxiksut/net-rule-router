use crate::interfaces_routes::{
    format_interface_row_for_contract, render_interfaces_and_routes_screen,
};
use crate::rules::render_rules_screen;
use crate::security::render_screen_only_security_status;
use crate::settings::render_settings_screen;
use nrr_application::backend_facade::diagnostics::{
    preview_active_security_alerts, preview_diagnostics_status,
};
use nrr_application::backend_facade::logs::{
    preview_audit_entries_first_page, preview_operational_logs_first_page, AuditEntryFilter,
    LogEntryFilter, PaginationParams,
};
use nrr_application::backend_facade::network_interfaces::{
    interface_diagnostics_checks_snapshot, interfaces_routes_preview_snapshot,
    RouteSelectionRequest,
};
use nrr_application::backend_facade::rules::RulesScreenRequest;
use nrr_application::backend_facade::{
    BackendConnectionStatus, BackendFacade, BackendProviderKind,
};
use nrr_application::route_bindings::{
    format_route_bindings_export, route_bindings_export_snapshot,
};
use nrr_shared::{
    load_locale_catalog, load_locale_descriptors, load_locale_reports, resolve_catalog_text,
    ActivationSource, AppSection, AppShellModel, LocaleLoadStatus, RouteBehaviorMode, ThemeMode,
};
use nrr_ui_support::first_run::FirstRunFlowSnapshot;
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::ui_preferences::{canonicalize_language_id, SystemFontFamily, UiPreferences};
use serde::Deserialize;
use serde_json::json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PREFERENCES_MARKER: &str = "NRR_PREFS_JSON:";

pub fn render_first_run_wizard(first_run: &FirstRunFlowSnapshot) {
    println!("First-run wizard:");
    println!("- required={}", first_run.wizard_required);
    println!("- scenario={}", first_run.selected_scenario.title());
    println!(
        "- available scenarios={}",
        first_run
            .available_scenarios
            .iter()
            .map(|scenario| scenario.title())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "- quick-start path={}",
        first_run
            .quick_start_path_sections
            .iter()
            .map(|section| section.title())
            .collect::<Vec<_>>()
            .join(" -> ")
    );
}

pub fn render_main_window_frame(shell: &AppShellModel, section: AppSection) {
    println!(
        "Main window frame: title='{}', section='{}'",
        shell.main_window_shell.window_title,
        section.title()
    );
    println!(
        "Main menu groups: {}",
        shell
            .menu_bar
            .iter()
            .map(|group| group.id.title())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

pub fn render_section_shell(
    shell: &AppShellModel,
    section: AppSection,
    preferences: UiPreferences,
) {
    match section {
        AppSection::InterfacesAndRoutes => render_interfaces_and_routes_screen(shell),
        AppSection::Rules => render_rules_screen(shell),
        AppSection::Diagnostics => render_diagnostics_screen(shell),
        AppSection::Logs => render_logs_screen(),
        AppSection::Settings => render_settings_screen(shell, preferences),
    }

    render_screen_only_security_status(shell);
}

pub fn run_interactive_window(
    _shell: AppShellModel,
    _section_to_open: AppSection,
    _source: ActivationSource,
    preferences: UiPreferences,
    _first_run: FirstRunFlowSnapshot,
    request: &crate::app_shell::LaunchRequest,
) -> Result<UiPreferences, String> {
    let qml_main = resolve_qml_main_path()
        .ok_or_else(|| "Qt runtime file is missing: apps/desktop/qml/Main.qml".to_string())?;
    let qml_argument = format!("--qml={}", qml_main.display());
    let backend_executable = env::current_exe()
        .map_err(|error| format!("Failed to resolve GUI backend executable path: {error}"))?;
    let mut host_arguments = vec![
        qml_argument,
        format!("--nrr-backend-exe={}", backend_executable.display()),
    ];
    for backend_argument in serialize_backend_arguments(request) {
        host_arguments.push(format!("--nrr-backend-arg={backend_argument}"));
    }
    if let Some(icon_path) = resolve_native_icon_path() {
        host_arguments.push(format!("--nrr-app-icon={}", icon_path.display()));
    }
    if let Ok(raw_ms) = env::var("NRR_QML_AUTOCLOSE_MS") {
        if let Ok(parsed_ms) = raw_ms.trim().parse::<u64>() {
            if parsed_ms > 0 {
                host_arguments.push(format!("--nrr-auto-close-ms={parsed_ms}"));
            }
        }
    }

    let output_result = run_qt_host_command(&host_arguments);

    let output = match output_result {
        Ok(output) => output,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                return Err(
                    "Qt host executable was not found. Build `nrr-qt-host` or ensure `cargo` is available in PATH."
                        .to_string(),
                );
            }
            return Err(format!("Failed to launch Qt host runtime: {error}"));
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let updated_preferences = parse_preferences_from_qt_output(preferences, &stdout, &stderr)?;

    if !output.status.success() {
        return Err(format!(
            "Qt host runtime exited with status {}.\nstdout:\n{}\nstderr:\n{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }

    Ok(updated_preferences)
}

fn serialize_backend_arguments(request: &crate::app_shell::LaunchRequest) -> Vec<String> {
    let mut arguments = vec![format!("--source={}", request.source)];
    if let Some(section) = request.section {
        arguments.push(format!("--section={section}"));
    }
    if request.open_about {
        arguments.push("--about".to_string());
    }
    if request.open_license {
        arguments.push("--license".to_string());
    }
    if let Some(first_run_completed) = request.first_run_completed_override {
        arguments.push(format!(
            "--first-run={}",
            if first_run_completed {
                "completed"
            } else {
                "required"
            }
        ));
    }
    if let Some(scenario) = request.first_run_scenario_override {
        arguments.push(format!("--scenario={}", scenario.slug()));
    }
    arguments
}

fn render_diagnostics_screen(shell: &AppShellModel) {
    let status = preview_diagnostics_status();
    let alerts = preview_active_security_alerts();
    let request = RouteSelectionRequest::default();
    let adapters = interfaces_routes_preview_snapshot(request.clone());
    let checks_snapshot = interface_diagnostics_checks_snapshot(request);
    println!("Diagnostics screen (preview data):");
    println!(
        "- overall: healthy={} stale={}",
        status.overall_healthy, status.stale
    );
    println!(
        "- service: state={} revision={:?} pending={}",
        status.service_health.state,
        status.service_health.active_revision_id,
        status.service_health.pending_changes
    );
    println!(
        "- security: audit_chain_ok={} write_healthy={} active_alerts={}",
        status.security_status.audit_chain_ok,
        status.security_status.audit_write_healthy,
        status.security_status.active_alert_count
    );
    for alert in &alerts {
        println!(
            "  alert {}: kind={} state={} reason={} requires_action={}",
            alert.alert_id, alert.kind, alert.state, alert.reason_code, alert.requires_action
        );
    }
    println!(
        "- cache: entries={} healthy={} rebuilding={}",
        status.cache_health.entry_count,
        status.cache_health.healthy,
        status.cache_health.rebuilding
    );
    println!(
        "- logs: writable={} size_bytes={} files={} dropped={}",
        status.log_health.dir_writable,
        status.log_health.total_size_bytes,
        status.log_health.file_count,
        status.log_health.dropped_count
    );
    println!(
        "- diagnostic_mode: active={} scope={:?} expires_at={:?}",
        status.diagnostic_mode.active,
        status.diagnostic_mode.scope_key,
        status.diagnostic_mode.expires_at
    );
    println!(
        "- Adapter fields format (shared with interfaces/explain): unknown='{}'",
        shell.interfaces_routes.display_format.unknown_value_marker
    );
    println!("- Adapter snapshot:");
    for row in &adapters.rows {
        println!("  {}", format_interface_row_for_contract(shell, row));
    }
    println!("- Adapter checks: {}", checks_snapshot.integration_note);
    for row in &checks_snapshot.rows {
        println!("  {}:", row.windows_name);
        for check in &row.checks {
            println!(
                "    {} -> {} ({})",
                check.action.title(),
                check.status.title(),
                check.explanation
            );
        }
    }
}

fn render_logs_screen() {
    let page = preview_operational_logs_first_page();
    let audit_page = preview_audit_entries_first_page();
    println!("Logs screen (preview data):");
    println!(
        "- operational: {} entries (page), next_cursor={:?}",
        page.items.len(),
        page.next_cursor.as_ref().map(|c| c.as_str().to_string())
    );
    for entry in &page.items {
        println!(
            "  {} [{}/{}] {} :: {}",
            entry.created_at, entry.level, entry.category, entry.kind, entry.message_key
        );
    }
    println!(
        "- audit: {} entries (page), next_cursor={:?}",
        audit_page.items.len(),
        audit_page
            .next_cursor
            .as_ref()
            .map(|c| c.as_str().to_string())
    );
    for entry in &audit_page.items {
        println!(
            "  seq={} kind={} result={} reason={} revision={:?}",
            entry.seq, entry.kind, entry.result, entry.reason_code, entry.revision_id
        );
    }
}

fn resolve_qml_main_path() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_QML_MAIN") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join("Main.qml");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    let cwd_candidate = env::current_dir().ok()?.join("apps/desktop/qml/Main.qml");
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    None
}

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

fn resolve_native_icon_path() -> Option<PathBuf> {
    // Installed / portable layout first: the icon next to the running
    // executable (walk a few levels up so a redirected target-dir / a
    // nested install tree resolves), then the dev source tree, then cwd.
    if let Ok(exe) = env::current_exe() {
        let mut dir = exe.parent();
        for _ in 0..6 {
            let Some(d) = dir else { break };
            let candidate = d.join("assets/icons/app/app.ico");
            if candidate.exists() {
                return Some(candidate);
            }
            dir = d.parent();
        }
    }

    let manifest_candidate =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets/icons/app/app.ico");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    let cwd_candidate = env::current_dir().ok()?.join("assets/icons/app/app.ico");
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    None
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
    // The service writes operational logs to
    // `%ProgramData%\NetRuleRouter\logs` (`Users:RX` ACL applied at
    // install). The user-facing "Open logs folder" action MUST land
    // there or the user sees an empty directory.
    let mut candidates = Vec::new();
    if let Some(program_data) = env::var_os("ProgramData") {
        candidates.push(
            PathBuf::from(program_data)
                .join("NetRuleRouter")
                .join("logs"),
        );
    }
    candidates.push(PathBuf::from(r"C:\ProgramData\NetRuleRouter\logs"));
    // Fallbacks for environments where the service isn't installed
    // (dev/test). We do NOT create the ProgramData fallback — the
    // service owns that path and the GUI shouldn't be racing the
    // ACL setup. Per-user candidates remain as last resort.
    if let Some(local_app_data) = env::var_os("LOCALAPPDATA") {
        candidates.push(
            PathBuf::from(local_app_data)
                .join("NetRuleRouter")
                .join("logs"),
        );
    }
    if let Some(app_data) = env::var_os("APPDATA") {
        candidates.push(PathBuf::from(app_data).join("NetRuleRouter").join("logs"));
    }
    candidates.push(env::temp_dir().join("NetRuleRouter").join("logs"));

    // Existing path wins; only fall through to create when nothing
    // is present (development scenario where the service has never
    // written anything yet).
    if let Some(existing) = candidates.iter().find(|p| p.is_dir()) {
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
#[allow(deprecated)]
#[allow(clippy::too_many_arguments)] // context emitter threads the full UI surface
pub fn write_qt_context_file_at(
    file_path: &Path,
    shell: &AppShellModel,
    section_to_open: AppSection,
    source: ActivationSource,
    preferences: UiPreferences,
    first_run: &FirstRunFlowSnapshot,
    request: &crate::app_shell::LaunchRequest,
    backend: &dyn BackendFacade,
    backend_status: &BackendConnectionStatus,
) -> Result<(), String> {
    let locale_catalog = load_locale_catalog();
    let locale_descriptors = load_locale_descriptors();
    let locale_reports = load_locale_reports();
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
    let interfaces_snapshot = backend.interfaces_snapshot(interfaces_request);
    let diagnostics_checks_snapshot =
        backend.interface_checks_snapshot(base_route_selection_request);
    let rules_snapshot = backend.rules_snapshot(RulesScreenRequest::default());
    let diagnostics_status = backend.diagnostics_status_snapshot();
    let active_alerts = backend.list_security_alerts(None);
    let logs_page =
        backend.list_log_entries(&LogEntryFilter::default(), &PaginationParams::default());
    let audit_page =
        backend.list_audit_entries(&AuditEntryFilter::default(), &PaginationParams::default());
    let security_snapshot = backend.status_snapshot();
    let bindings_snapshot =
        route_bindings_export_snapshot(&preferences, security_snapshot.active_revision);
    let bindings_export_text = format_route_bindings_export(&bindings_snapshot);
    let about = nrr_application::about_window_info();
    let resolved_theme = resolve_theme(preferences.theme_mode);
    let icon_file_url = resolve_icon_path()
        .as_ref()
        .map(|path| path_to_file_url(path));
    let logs_folder_url = resolve_logs_directory()
        .as_ref()
        .map(|path| path_to_file_url(path));
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
    let rules_rows_json: Vec<serde_json::Value> = rules_snapshot
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
        .collect();
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

    let backend_status_payload = backend_connection_status_to_payload(backend_status);
    let backend_service_backed = backend_provider_is_service_backed(backend.provider_kind());
    // Capability descriptor for the running OS. The QML renders
    // capability-driven (a section shows only when `supports.<feature>` is
    // true), so OS knowledge stays in Rust and never leaks into a
    // `Qt.platform.os` branch in QML.
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
        "activationSource": source.slug(),
        "backendStatus": backend_status_payload,
        // Whether the cold-start facade actually talks to the service. A
        // mock/preview launch reports `backendStatus.kind == "connected"`
        // without a service behind it, and the GUI must park routing changes
        // in that case instead of pretending they were applied.
        "backendServiceBacked": backend_service_backed,
        "iconFileUrl": icon_file_url,
        "platformProfile": platform_profile,
        "startupDialog": if request.open_license {
            Some("license")
        } else if request.open_about {
            Some("about")
        } else {
            None::<&str>
        },
        "preferences": {
            "launchWindowOnStartup": preferences.launch_window_on_startup,
            "minimizeToTrayInsteadOfClose": preferences.minimize_to_tray_instead_of_close,
            "showNotifications": preferences.show_notifications,
            "notifySuggestionChanges": preferences.notify_suggestion_changes,
            "notifyBlockNotices": preferences.notify_block_notices,
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
            "blockSecondaryWhenUnavailable": preferences.block_secondary_traffic_when_unavailable,
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
            "preFlightApplyPolicyOptIn": preferences.pre_flight_apply_policy_opt_in,
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
            "previewNotice": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "interfaces.preview-notice",
                interfaces_snapshot.preview_notice,
            ),
            "roleExplanation": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "interfaces.role-explanation",
                interfaces_snapshot.role_explanation,
            ),
            "dataScopeNote": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "interfaces.data-scope-note",
                interfaces_snapshot.data_scope_note,
            ),
            "dataSource": interfaces_snapshot.data_source.title(),
            "selectedBehaviorMode": interfaces_snapshot.selected_behavior_mode.slug(),
            "recommendationPolicyNote": interfaces_snapshot.recommendation_policy_note,
            "roleAssignmentAdvisory": interfaces_role_assignment_advisory,
            "supportedBehaviorModes": interfaces_snapshot.supported_behavior_modes.iter().map(|mode| json!({
                "id": mode.slug(),
                "label": mode.user_label(),
            })).collect::<Vec<_>>(),
            "rows": interface_rows_json,
            "routeBindings": {
                "activeRevision": bindings_snapshot.active_revision,
                "behaviorMode": bindings_snapshot.behavior_mode.slug(),
                "changeClass": bindings_snapshot.change_class.title(),
                "revisionLinkPolicy": bindings_snapshot.revision_link_policy,
                "changeClassificationPolicy": bindings_snapshot.change_classification_policy,
                "primary": {
                    "persistentId": bindings_snapshot.primary.persistent_id,
                    "adapterName": bindings_snapshot.primary.adapter_name,
                    "userConfirmed": bindings_snapshot.primary.user_confirmed,
                    "resolutionState": bindings_snapshot.primary.resolution_state.title(),
                },
                "secondary": {
                    "persistentId": bindings_snapshot.secondary.persistent_id,
                    "adapterName": bindings_snapshot.secondary.adapter_name,
                    "userConfirmed": bindings_snapshot.secondary.user_confirmed,
                    "resolutionState": bindings_snapshot.secondary.resolution_state.title(),
                },
                "exportPreview": bindings_export_text,
            },
        },
        "rules": {
            "previewNotice": resolve_catalog_text(
                &locale_catalog,
                &preferences.language,
                "rules.preview-notice",
                rules_snapshot.preview_notice,
            ),
            "supportedRuleTypes": supported_rule_types,
            "rows": rules_rows_json,
        },
        "diagnostics": {
            "overallHealthy": diagnostics_status.overall_healthy,
            "stale": diagnostics_status.stale,
            "serviceHealth": {
                "state": diagnostics_status.service_health.state,
                "activeRevisionId": diagnostics_status.service_health.active_revision_id,
                "pendingChanges": diagnostics_status.service_health.pending_changes,
            },
            "securityStatus": {
                "auditChainOk": diagnostics_status.security_status.audit_chain_ok,
                "activeAlertCount": diagnostics_status.security_status.active_alert_count,
                "auditWriteHealthy": diagnostics_status.security_status.audit_write_healthy,
            },
            "activeAlerts": active_alerts.iter().map(|alert| json!({
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
                "rebuilding": diagnostics_status.cache_health.rebuilding,
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
            "adapterChecksIntegrationNote": diagnostics_checks_snapshot.integration_note,
            "adapterChecks": diagnostics_checks_snapshot.rows.iter().map(|row| json!({
                "persistentId": row.persistent_id,
                "name": row.windows_name,
                "checks": row.checks.iter().map(|check| json!({
                    "id": check.action.slug(),
                    "title": check.action.title(),
                    "status": check.status.title(),
                    "explanation": check.explanation,
                    "readOnly": check.read_only,
                    "requiresServiceMediation": check.requires_service_mediation,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
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
                "auditSizeBytes": 1_120_000_u64,
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

    let payload =
        serde_json::to_string_pretty(&context).map_err(|error| format!("JSON error: {error}"))?;
    fs::write(file_path, payload)
        .map_err(|error| format!("Failed to write Qt context file: {error}"))?;
    Ok(())
}

fn parse_preferences_from_qt_output(
    current: UiPreferences,
    stdout: &str,
    stderr: &str,
) -> Result<UiPreferences, String> {
    let mut payload_line = None::<String>;

    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(index) = line.find(PREFERENCES_MARKER) {
            let value = line[(index + PREFERENCES_MARKER.len())..].trim();
            if !value.is_empty() {
                payload_line = Some(value.to_string());
            }
        }
    }

    let Some(serialized_payload) = payload_line else {
        return Ok(current);
    };

    let payload: QtPreferencesPayload = serde_json::from_str(&serialized_payload)
        .map_err(|error| format!("Failed to parse Qt preferences payload: {error}"))?;
    Ok(payload.apply_over(current))
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

fn run_qt_host_command(host_arguments: &[String]) -> Result<std::process::Output, std::io::Error> {
    if let Some(qt_host_executable) = resolve_qt_host_executable() {
        return Command::new(qt_host_executable)
            .args(host_arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
    }

    let Some(workspace_root) = resolve_workspace_root() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "workspace root was not found for launching nrr-qt-host",
        ));
    };

    Command::new("cargo")
        .current_dir(workspace_root)
        .arg("run")
        .arg("-p")
        .arg("nrr-qt-host")
        .arg("--")
        .args(host_arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
}

fn resolve_qt_host_executable() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_QT_HOST_EXE") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = if cfg!(windows) {
        "nrr-qt-host.exe"
    } else {
        "nrr-qt-host"
    };

    // Look adjacent to the running binary first. This is the only path that
    // works regardless of `[build] target-dir` redirects — the Cargo manifest
    // path baked at compile time can point to a directory that does not hold
    // the actual artifacts when target-dir was moved (e.g. to a fast local
    // drive away from a synced source tree).
    if let Ok(current_executable) = env::current_exe() {
        if let Some(parent) = current_executable.parent() {
            let candidate = parent.join(executable_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    for profile in ["debug", "release"] {
        let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../target")
            .join(profile)
            .join(executable_name);
        if manifest_candidate.exists() {
            return Some(manifest_candidate);
        }
    }

    None
}

fn resolve_workspace_root() -> Option<PathBuf> {
    let manifest_workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    if manifest_workspace.join("Cargo.toml").exists() {
        return Some(manifest_workspace);
    }

    let mut directory = env::current_dir().ok()?;
    loop {
        if directory.join("Cargo.toml").exists() {
            return Some(directory);
        }
        if !directory.pop() {
            break;
        }
    }

    None
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QtPreferencesPayload {
    launch_window_on_startup: bool,
    minimize_to_tray_instead_of_close: bool,
    show_notifications: bool,
    /// Additive: a payload written before the per-kind mute existed leaves the
    /// stripe enabled, which is the pre-existing behaviour.
    #[serde(default = "default_true")]
    notify_suggestion_changes: bool,
    /// Additive: a payload written before this mute existed leaves the
    /// block-notice notification enabled, which is the pre-existing behaviour.
    #[serde(default = "default_true")]
    notify_block_notices: bool,
    /// Additive: a payload written before this existed leaves addresses
    /// visible, which is the pre-existing behaviour.
    #[serde(default)]
    hide_block_notice_addresses: bool,
    reopen_last_section_on_startup: bool,
    first_run_completed: bool,
    // EULA acceptance version. `#[serde(default)]` (→ 0 = not accepted) keeps
    // the round-trip backward-compatible with QML builds that don't emit the
    // key, matching the safe default (re-prompt the agreement).
    #[serde(default)]
    accepted_eula_version: u32,
    theme_mode: String,
    accessibility_high_contrast: bool,
    font_scale_percent: u16,
    system_font: String,
    enhanced_focus: bool,
    simplified_labels: bool,
    tooltips_enabled: bool,
    language: String,
    route_primary_label: String,
    route_secondary_label: String,
    #[serde(default)]
    selected_primary_interface_id: String,
    selected_primary_interface_name: String,
    #[serde(default)]
    primary_role_user_confirmed: bool,
    #[serde(default)]
    selected_secondary_interface_id: String,
    selected_secondary_interface_name: String,
    #[serde(default)]
    secondary_role_user_confirmed: bool,
    route_behavior_mode: String,
    // `#[serde(default)]` (→ false) keeps the round-trip backward-compatible
    // with QML builds that don't emit the key, and matches the safe default
    // (kill-switch off).
    #[serde(default)]
    block_secondary_when_unavailable: bool,
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
    // Pre-flight apply-failure policy opt-in. `#[serde(default)]` (→ false)
    // keeps the round-trip backward-compatible with QML builds that don't
    // emit the key and matches the safe default (option hidden from the
    // picker unless already selected).
    #[serde(default)]
    pre_flight_apply_policy_opt_in: bool,
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
    last_opened_section: String,

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
    // `apply_over` writes the legacy policy fields back into
    // `UiPreferences` for round-trip parity with Qt's legacy preferences
    // shape. The launcher's migration flow then zeroes them via
    // `cleanup_legacy_policy_fields` once the per-SID service-owned
    // values have been written through IPC.
    #[allow(deprecated)]
    fn apply_over(self, mut current: UiPreferences) -> UiPreferences {
        current.launch_window_on_startup = self.launch_window_on_startup;
        current.minimize_to_tray_instead_of_close = self.minimize_to_tray_instead_of_close;
        current.show_notifications = self.show_notifications;
        current.notify_suggestion_changes = self.notify_suggestion_changes;
        current.notify_block_notices = self.notify_block_notices;
        current.hide_block_notice_addresses = self.hide_block_notice_addresses;
        current.reopen_last_section_on_startup = self.reopen_last_section_on_startup;
        current.first_run_completed = self.first_run_completed;
        current.accepted_eula_version = self.accepted_eula_version;

        current.theme_mode = self
            .theme_mode
            .parse::<ThemeMode>()
            .unwrap_or(current.theme_mode);
        if self.accessibility_high_contrast {
            current.theme_mode = ThemeMode::HighContrast;
        }
        current.accessibility_high_contrast = current.theme_mode == ThemeMode::HighContrast;
        current.accessibility_ui_font_scale_percent = self.font_scale_percent.clamp(80, 300);
        current.accessibility_system_font = self
            .system_font
            .parse::<SystemFontFamily>()
            .unwrap_or(current.accessibility_system_font);
        current.accessibility_enhanced_focus_indicator = self.enhanced_focus;
        current.accessibility_simplified_labels = self.simplified_labels;
        current.tooltips_enabled = self.tooltips_enabled;
        if let Some(language_id) = canonicalize_language_id(&self.language) {
            current.language = language_id;
        }
        if !self.route_primary_label.trim().is_empty() {
            current.route_primary_label = self.route_primary_label;
        }
        if !self.route_secondary_label.trim().is_empty() {
            current.route_secondary_label = self.route_secondary_label;
        }
        current.selected_primary_interface_id = self.selected_primary_interface_id;
        current.selected_primary_interface_name = self.selected_primary_interface_name;
        current.primary_role_user_confirmed = self.primary_role_user_confirmed;
        current.selected_secondary_interface_id = self.selected_secondary_interface_id;
        current.selected_secondary_interface_name = self.selected_secondary_interface_name;
        current.secondary_role_user_confirmed = self.secondary_role_user_confirmed;
        current.route_behavior_mode = self
            .route_behavior_mode
            .parse::<RouteBehaviorMode>()
            .unwrap_or(current.route_behavior_mode);
        current.block_secondary_traffic_when_unavailable = self.block_secondary_when_unavailable;
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
        // applied/discarded" and must clear the stored value). Structural
        // gate mirrors the ui-support parser: a payload
        // that is not a single-line `{…}` object (or is oversized) resets to
        // empty rather than corrupting the line-oriented preferences file.
        current.route_pending_offline_json = if self.route_pending_offline_json.is_empty()
            || (self.route_pending_offline_json.len() <= 8 * 1024
                && self.route_pending_offline_json.starts_with('{')
                && self.route_pending_offline_json.ends_with('}')
                && !self.route_pending_offline_json.contains(['\n', '\r']))
        {
            self.route_pending_offline_json
        } else {
            String::new()
        };
        // Cache-viewer column widths — unconditional carry (empty clears to
        // defaults). Same structural gate as the pending-offline blob: a value
        // that is not a single-line `{…}` object (or is oversized) resets to
        // empty rather than corrupting the line-oriented preferences file.
        current.cache_table_column_widths = if self.cache_table_column_widths.is_empty()
            || (self.cache_table_column_widths.len() <= 8 * 1024
                && self.cache_table_column_widths.starts_with('{')
                && self.cache_table_column_widths.ends_with('}')
                && !self.cache_table_column_widths.contains(['\n', '\r']))
        {
            self.cache_table_column_widths
        } else {
            String::new()
        };
        // Last-known service-owned values — unconditional carry (an EMPTY
        // string is the legitimate "nothing mirrored yet" state). Same
        // structural gate as the two blobs above: a value that is not a
        // single-line `{…}` object (or is oversized) resets to empty rather
        // than corrupting the line-oriented preferences file.
        current.service_backed_mirror_json = if self.service_backed_mirror_json.is_empty()
            || (self.service_backed_mirror_json.len() <= 8 * 1024
                && self.service_backed_mirror_json.starts_with('{')
                && self.service_backed_mirror_json.ends_with('}')
                && !self.service_backed_mirror_json.contains(['\n', '\r']))
        {
            self.service_backed_mirror_json
        } else {
            String::new()
        };
        // The user's intent for those same settings — same unconditional
        // carry and same structural gate. A blob that fails the gate resets to
        // "no intent recorded"; replaying a half-parsed intent to the service
        // would be worse than replaying none.
        current.service_intent_json = if self.service_intent_json.is_empty()
            || (self.service_intent_json.len() <= 8 * 1024
                && self.service_intent_json.starts_with('{')
                && self.service_intent_json.ends_with('}')
                && !self.service_intent_json.contains(['\n', '\r']))
        {
            self.service_intent_json
        } else {
            String::new()
        };
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
        current.pre_flight_apply_policy_opt_in = self.pre_flight_apply_policy_opt_in;
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
            if !sig.contains(['\n', '\r']) {
                current.unenforced_apps_ack_signature = sig;
            }
        }
        // Key present → take the value (single line only, so the
        // line-oriented prefs file stays intact); key absent (older QML) →
        // keep stored.
        if let Some(path) = self.confirmed_vpn_exe_path {
            if !path.contains(['\n', '\r']) {
                current.confirmed_vpn_exe_path = path;
            }
        }
        // Key present → take the whole set (single line only); key
        // absent (older QML) → keep stored.
        if let Some(paths) = self.confirmed_vpn_exe_paths {
            if !paths.contains(['\n', '\r']) {
                current.confirmed_vpn_exe_paths = paths;
            }
        }
        current.last_opened_section = self
            .last_opened_section
            .parse::<AppSection>()
            .unwrap_or(current.last_opened_section);

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
        current.auto_load_rules_on_launch = self.auto_load_rules_on_launch;
        current.export_include_comments = self.export_include_comments;
        current.import_only_active = self.import_only_active;
        current.compat_banner_mode = self.compat_banner_mode;
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
        current.merge_conflict_policy = self.merge_conflict_policy;
        current.secondary_split_ack_adapter_name = self.secondary_split_ack_adapter_name;

        current
    }
}

// ── Backend status payload helper ─────────────────────────────────────────

/// Maps a [`BackendConnectionStatus`] to the kebab-case JSON shape
/// consumed by `Main.qml`'s connection banner. Shape:
///
/// - `kind = "connected" | "connecting" | "disconnected" | "service-stopped" | "service-not-installed" | "protocol-mismatch"`
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
