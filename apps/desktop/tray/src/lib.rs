//! Library surface of the legacy tray orchestrator crate.
//!
//! See `apps/desktop/gui/src/lib.rs` for the rationale; the same pattern is
//! used here so `nrr-launcher` can call into `write_qt_tray_context_file`
//! without duplicating logic.

use nrr_application::backend_facade::{mock_scenario_from_env, tray_status_for_mock_scenario};
use nrr_shared::{
    format_shell_summary, gui_shell_v1, load_locale_catalog, load_locale_reports,
    resolve_catalog_text, AppAction, AppSection, LocaleLoadStatus, LocaleSource,
    SetupActionAvailability,
};
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::tray::{
    tray_runtime_snapshot, TrayActionRuntime, TrayRuntimeSnapshot, TrayServiceLink, TrayStatusKind,
};
use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrayLaunchOptions {
    first_run_completed_override: Option<bool>,
    status_override: Option<TrayStatusKind>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperCommand {
    EmitTrayContext {
        output_path: PathBuf,
        options: TrayLaunchOptions,
    },
}

pub fn run_app() {
    let raw_arguments = env::args().skip(1).collect::<Vec<_>>();
    if let Some(helper_command) = parse_helper_command(&raw_arguments) {
        if let Err(error) = run_helper_command(helper_command) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }

    println!("{}", nrr_application::runtime_boot_banner("tray"));
    println!("{}", nrr_application::runtime_boot_guard_message());

    let shell = gui_shell_v1();
    let launch = parse_launch_options_arguments(raw_arguments);
    let preferences = load_ui_preferences_with_fallback();
    let locale_reports = load_locale_reports();
    let rejected_locale_count = locale_reports
        .iter()
        .filter(|report| report.status == LocaleLoadStatus::Rejected)
        .count();
    let warning_locale_count = locale_reports
        .iter()
        .filter(|report| report.status == LocaleLoadStatus::AcceptedWithWarnings)
        .count();
    let rejected_user_locale_count = locale_reports
        .iter()
        .filter(|report| {
            report.status == LocaleLoadStatus::Rejected && report.source == LocaleSource::User
        })
        .count();
    let rejected_bundled_locale_count = locale_reports
        .iter()
        .filter(|report| {
            report.status == LocaleLoadStatus::Rejected && report.source == LocaleSource::Bundled
        })
        .count();
    let first_run_completed = launch
        .first_run_completed_override
        .unwrap_or(preferences.first_run_completed);
    let effective_status_override = resolve_effective_status_override(launch.status_override);
    let resolved_theme = resolve_theme(preferences.theme_mode);
    let runtime = tray_runtime_snapshot(
        &shell,
        first_run_completed,
        effective_status_override,
        resolved_theme.effective_mode,
        // This entry point never probes the service, so it must not claim to
        // know what is being enforced.
        TrayServiceLink::Unknown,
    );
    let locale_catalog = load_locale_catalog();
    let status_accessibility_text = resolve_tray_status_accessibility_text(
        &locale_catalog,
        &preferences.language,
        runtime.status_kind,
        runtime.status_line,
    );

    println!("Tray shell v1 initialized.");
    println!("{}", format_shell_summary(&shell));
    println!("Tray status: {}", runtime.status_line);
    println!(
        "Tray status accessibility text: {}",
        status_accessibility_text
    );
    println!("Tray icon asset hint: {}", runtime.icon_asset_hint);
    println!(
        "Tray theme: selected={}, effective={}, system={} (detected={})",
        resolved_theme.selected_mode.slug(),
        resolved_theme.effective_mode.slug(),
        resolved_theme.system_mode.slug(),
        resolved_theme.system_mode_detected
    );
    println!("Tray status presets: preview-mode | no-active-policy | service-unavailable");
    println!("{}", runtime.single_instance_note);
    if rejected_locale_count > 0 || warning_locale_count > 0 {
        println!(
            "Locale diagnostics: warnings={}, rejected={} (user={}, bundled={})",
            warning_locale_count,
            rejected_locale_count,
            rejected_user_locale_count,
            rejected_bundled_locale_count
        );
    }

    println!("Tray primary actions:");
    for item in &runtime.primary_actions {
        let label = resolve_action_label(&locale_catalog, &preferences.language, item.action);
        let description =
            resolve_action_accessibility_description(&locale_catalog, &preferences.language, item);
        println!(
            "- {} [{}; setup_gate={}]",
            label,
            if item.availability.is_enabled() {
                "enabled"
            } else {
                "preview"
            },
            item.setup_availability.title()
        );
        println!("  accessibility: {}", description);
    }

    println!("Tray quick actions:");
    for item in &runtime.quick_actions {
        let label = resolve_action_label(&locale_catalog, &preferences.language, item.action);
        let description =
            resolve_action_accessibility_description(&locale_catalog, &preferences.language, item);
        println!(
            "- {} [{}; setup_gate={}]",
            label,
            if item.availability.is_enabled() {
                "enabled"
            } else {
                "preview"
            },
            item.setup_availability.title()
        );
        println!("  accessibility: {}", description);
    }

    println!("Tray-to-GUI navigation uses contract-driven section actions.");

    if let Err(error) = run_qt_tray_runtime(&runtime, &preferences) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

pub fn parse_helper_command(arguments: &[String]) -> Option<HelperCommand> {
    let mut helper_name = None::<String>;
    let mut output_path = None::<PathBuf>;
    let mut launch_arguments = Vec::new();

    for argument in arguments {
        if let Some(value) = argument.strip_prefix("--nrr-helper=") {
            helper_name = Some(value.trim().to_string());
            continue;
        }
        if let Some(value) = argument.strip_prefix("--nrr-output=") {
            if !value.trim().is_empty() {
                output_path = Some(PathBuf::from(value.trim()));
            }
            continue;
        }
        launch_arguments.push(argument.clone());
    }

    match helper_name.as_deref() {
        Some("emit-tray-context") => Some(HelperCommand::EmitTrayContext {
            output_path: output_path?,
            options: parse_launch_options_arguments(launch_arguments),
        }),
        _ => None,
    }
}

pub fn run_helper_command(helper_command: HelperCommand) -> Result<(), String> {
    match helper_command {
        HelperCommand::EmitTrayContext {
            output_path,
            options,
        } => emit_tray_context(&output_path, options),
    }
}

pub fn parse_launch_options_arguments<I>(arguments: I) -> TrayLaunchOptions
where
    I: IntoIterator<Item = String>,
{
    let mut options = TrayLaunchOptions {
        first_run_completed_override: None,
        status_override: None,
    };

    for argument in arguments {
        if let Some(value) = argument.strip_prefix("--first-run=") {
            options.first_run_completed_override = match value {
                "required" | "pending" => Some(false),
                "completed" | "done" => Some(true),
                _ => {
                    eprintln!(
                        "Unknown --first-run value '{}'. Use required|completed.",
                        value
                    );
                    None
                }
            };
            continue;
        }

        if let Some(value) = argument.strip_prefix("--status=") {
            match value.parse::<TrayStatusKind>() {
                Ok(status) => options.status_override = Some(status),
                Err(_) => eprintln!(
                    "Unknown --status value '{}'. Use preview-mode|no-active-policy|service-unavailable.",
                    value
                ),
            }
            continue;
        }

        eprintln!("Unknown tray launch argument '{}'.", argument);
    }

    options
}

pub fn resolve_effective_status_override(
    cli_override: Option<TrayStatusKind>,
) -> Option<TrayStatusKind> {
    cli_override.or_else(|| {
        let scenario = mock_scenario_from_env()?;
        tray_status_for_mock_scenario(scenario)
    })
}

pub fn load_ui_preferences_with_fallback() -> UiPreferences {
    match UiPreferencesStore::managed_local() {
        Ok(store) => store.load().unwrap_or_else(|error| {
            eprintln!(
                "Failed to read UI preferences from '{}': {}",
                store.path().display(),
                error
            );
            UiPreferences::default()
        }),
        Err(error) => {
            eprintln!(
                "Failed to initialize UI preferences store for tray launch: {}",
                error
            );
            UiPreferences::default()
        }
    }
}

const QML_ACTION_MARKER: &str = "NRR_TRAY_ACTION:";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayActionContext {
    id: String,
    label: String,
    enabled: bool,
    accessible_description: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayContextPayload {
    language: String,
    locale_catalog: BTreeMap<String, BTreeMap<String, String>>,
    status_key: String,
    status_accessibility_key: String,
    status_line: String,
    status_accessibility_text: String,
    route_primary_label: String,
    route_secondary_label: String,
    icon_file_url: Option<String>,
    /// Mirrors the user's "show notifications" preference. The tray is the only
    /// surface that raises unsolicited windows, so it has to honour the toggle;
    /// it is a launch-time snapshot like `language` and `theme`, so a change
    /// takes effect the next time the tray starts.
    show_notifications: bool,
    /// Per-kind mute for the suggestions-changed stripe, under the master
    /// toggle above. Same launch-time snapshot rule.
    notify_suggestion_changes: bool,
    /// Per-kind mute for the "connection blocked" notice. The tray does not
    /// raise that notice itself today; carried through for parity with the
    /// main GUI context.
    notify_block_notices: bool,
    /// Whether the "connection blocked" notice hides the destination
    /// address. Same parity rule as `notify_block_notices`.
    hide_block_notice_addresses: bool,
    /// Mirrors the "Detailed routing mode" preference. The tray does not
    /// itself gate anything on it today; carried through for parity with the
    /// main GUI context.
    routing_detailed_mode: bool,
    theme: TrayThemeContext,
    primary_actions: Vec<TrayActionContext>,
    quick_actions: Vec<TrayActionContext>,
    /// OS capability descriptor, mirrored from the main GUI context so the
    /// tray can degrade capability-driven if it ever needs to.
    platform_profile: nrr_shared::platform_profile::PlatformProfile,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayThemeContext {
    selected_mode: String,
    effective_mode: String,
    system_mode: String,
    system_mode_detected: bool,
}

fn run_qt_tray_runtime(
    runtime: &TrayRuntimeSnapshot,
    preferences: &UiPreferences,
) -> Result<(), String> {
    let qml_tray = resolve_qml_tray_path()
        .ok_or_else(|| "Qt tray runtime file is missing: apps/desktop/qml/Tray.qml".to_string())?;
    let icon_file_url =
        resolve_asset_path(runtime.icon_asset_hint).map(|path| path_to_file_url(&path));
    let native_icon_path = resolve_asset_path(runtime.icon_asset_hint);
    let context_file =
        write_qt_tray_context_file(runtime, &preferences.language, preferences, icon_file_url)?;
    let context_file_url = path_to_file_url(&context_file);
    let auto_close_ms = env::var("NRR_QML_AUTOCLOSE_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0);
    let auto_close_deadline =
        auto_close_ms.map(|milliseconds| Instant::now() + Duration::from_millis(milliseconds));

    let mut host_arguments = vec![
        format!("--qml={}", qml_tray.display()),
        format!("--nrr-tray-context-file={context_file_url}"),
    ];
    if let Some(icon_path) = native_icon_path {
        host_arguments.push(format!("--nrr-app-icon={}", icon_path.display()));
    }
    if let Some(ms) = auto_close_ms {
        host_arguments.push(format!("--nrr-auto-close-ms={ms}"));
    }

    let mut command = build_qt_host_command(&host_arguments)?;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = fs::remove_file(&context_file);
            if error.kind() == std::io::ErrorKind::NotFound {
                return Err(
                    "Qt host executable was not found. Build `nrr-qt-host` or ensure `cargo` is available in PATH."
                        .to_string(),
                );
            }
            return Err(format!("Failed to launch Qt tray host runtime: {error}"));
        }
    };

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to capture Qt tray stdout.".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "Failed to capture Qt tray stderr.".to_string())?;

    let (sender, receiver) = mpsc::channel::<String>();
    spawn_qml_line_reader(stdout, sender.clone());
    spawn_qml_line_reader(stderr, sender.clone());
    drop(sender);

    let action_availability = collect_action_availability(runtime);

    let mut child_exit_status = None;
    let mut output_channel_closed = false;
    let mut terminated_by_auto_close = false;

    loop {
        match receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Err(error) = process_qml_line(&line, &action_availability) {
                    eprintln!("{error}");
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => output_channel_closed = true,
        }

        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("Failed to monitor Qt tray host runtime: {error}"))?
        {
            child_exit_status = Some(status);
            break;
        }

        if output_channel_closed {
            break;
        }

        if let Some(deadline) = auto_close_deadline {
            if Instant::now() >= deadline {
                if let Err(error) = child.kill() {
                    if error.kind() != std::io::ErrorKind::InvalidInput {
                        eprintln!(
                            "Failed to terminate Qt tray host runtime after auto-close timeout: {error}"
                        );
                    }
                }
                terminated_by_auto_close = true;
                break;
            }
        }
    }

    let status = match child_exit_status {
        Some(status) => status,
        None => child
            .wait()
            .map_err(|error| format!("Failed to wait for Qt tray host runtime: {error}"))?,
    };

    let _ = fs::remove_file(&context_file);

    if !status.success() && !terminated_by_auto_close {
        return Err(format!("Qt tray runtime exited with status {status}.",));
    }

    Ok(())
}

fn process_qml_line(line: &str, action_availability: &HashMap<String, bool>) -> Result<(), String> {
    if let Some(action_id) = parse_qml_action_marker(line) {
        if let Some(action) = tray_action_from_id(action_id) {
            let is_enabled = action_availability
                .get(action.id())
                .copied()
                .unwrap_or(true);
            dispatch_tray_action(action, is_enabled)?;
        } else {
            eprintln!("Unknown tray action from Qt runtime: '{action_id}'.");
        }
        return Ok(());
    }

    let trimmed = line.trim();
    if !trimmed.is_empty() {
        println!("{trimmed}");
    }

    Ok(())
}

fn collect_action_availability(runtime: &TrayRuntimeSnapshot) -> HashMap<String, bool> {
    let mut map = HashMap::new();

    for item in runtime
        .primary_actions
        .iter()
        .chain(runtime.quick_actions.iter())
    {
        map.insert(item.action.id().to_string(), item.availability.is_enabled());
    }

    map
}

fn parse_qml_action_marker(line: &str) -> Option<&str> {
    let marker_index = line.find(QML_ACTION_MARKER)?;
    let value = line[(marker_index + QML_ACTION_MARKER.len())..].trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn tray_action_from_id(action_id: &str) -> Option<AppAction> {
    if let Ok(section) = action_id.parse::<AppSection>() {
        return Some(AppAction::OpenSection(section));
    }

    match action_id {
        "open-main-window" => Some(AppAction::OpenMainWindow),
        "refresh-interfaces" => Some(AppAction::RefreshInterfaces),
        "check-service-status" => Some(AppAction::CheckServiceStatus),
        "safe-rollback" => Some(AppAction::SafeRollback),
        "temporary-disable-product-impact" => Some(AppAction::TemporarilyDisableProductImpact),
        "open-about-window" => Some(AppAction::OpenAboutWindow),
        "open-license-window" => Some(AppAction::OpenLicenseWindow),
        "open-logs-folder" => Some(AppAction::OpenLogsFolder),
        "check-for-updates" => Some(AppAction::CheckForUpdates),
        "exit-application" => Some(AppAction::ExitApplication),
        "load-rule-list" => Some(AppAction::LoadRuleList),
        "import-preset" => Some(AppAction::ImportPreset),
        "export-current-rule-list" => Some(AppAction::ExportCurrentRuleList),
        _ => None,
    }
}

fn dispatch_tray_action(action: AppAction, is_enabled: bool) -> Result<(), String> {
    if !is_enabled {
        println!(
            "Tray action '{}' is preview-only in the current setup state.",
            action.id()
        );
        return Ok(());
    }

    match action {
        AppAction::OpenMainWindow => launch_gui_action(None, false, false),
        AppAction::OpenSection(section) => launch_gui_action(Some(section), false, false),
        AppAction::RefreshInterfaces => {
            println!("Tray quick action: refresh interfaces (opens Interfaces and routes screen).");
            launch_gui_action(Some(AppSection::InterfacesAndRoutes), false, false)
        }
        AppAction::CheckServiceStatus => {
            println!("Tray quick action: check service status (opens Diagnostics screen).");
            launch_gui_action(Some(AppSection::Diagnostics), false, false)
        }
        AppAction::SafeRollback => {
            println!("Tray quick action: safe rollback (preview). Opening Diagnostics screen.");
            launch_gui_action(Some(AppSection::Diagnostics), false, false)
        }
        AppAction::TemporarilyDisableProductImpact => {
            println!(
                "Tray quick action: disable product impact (preview). Opening Diagnostics screen."
            );
            launch_gui_action(Some(AppSection::Diagnostics), false, false)
        }
        AppAction::OpenAboutWindow => launch_gui_action(None, true, false),
        AppAction::OpenLicenseWindow => launch_gui_action(None, false, true),
        AppAction::OpenLogsFolder => open_logs_folder(),
        AppAction::ExitApplication => Ok(()),
        AppAction::LoadRuleList
        | AppAction::UpdateRulesFromFile
        | AppAction::ImportPreset
        | AppAction::ExportCurrentRuleList
        | AppAction::CheckForUpdates => {
            println!(
                "Tray action '{}' is declared in shell contracts but not bound in block 2 tray menu.",
                action.id()
            );
            Ok(())
        }
    }
}

fn launch_gui_action(
    section: Option<AppSection>,
    open_about: bool,
    open_license: bool,
) -> Result<(), String> {
    let mut backend_args = vec!["--source=tray".to_string()];
    if let Some(section) = section {
        backend_args.push(format!("--section={section}"));
    }
    if open_about {
        backend_args.push("--about".to_string());
    }
    if open_license {
        backend_args.push("--license".to_string());
    }

    let mut host_arguments = Vec::new();
    if let Some(qml_main) = resolve_qml_main_path() {
        host_arguments.push(format!("--qml={}", qml_main.display()));
    }
    if let Some(gui_backend_executable) = resolve_gui_backend_executable() {
        host_arguments.push(format!(
            "--nrr-backend-exe={}",
            gui_backend_executable.display()
        ));
    }
    if let Some(icon_path) = resolve_asset_path("assets/icons/app/app.ico") {
        host_arguments.push(format!("--nrr-app-icon={}", icon_path.display()));
    }
    host_arguments.extend(
        backend_args
            .into_iter()
            .map(|argument| format!("--nrr-backend-arg={argument}")),
    );

    if let Some(native_gui_executable) = resolve_native_gui_executable() {
        let mut command = Command::new(native_gui_executable);
        command.args(&host_arguments);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
            .spawn()
            .map_err(|error| format!("Failed to launch native GUI executable: {error}"))?;
        return Ok(());
    }

    let mut command = build_qt_host_command(&host_arguments)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    command
        .spawn()
        .map_err(|error| format!("Failed to launch main GUI via Qt host: {error}"))?;

    Ok(())
}

fn open_logs_folder() -> Result<(), String> {
    let logs_directory = resolve_logs_directory()
        .ok_or_else(|| "Failed to resolve the managed logs directory.".to_string())?;
    Command::new("explorer.exe")
        .arg(&logs_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            format!(
                "Failed to open logs directory '{}': {error}",
                logs_directory.display()
            )
        })?;
    Ok(())
}

fn resolve_logs_directory() -> Option<PathBuf> {
    let mut candidates = Vec::new();
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

    candidates
        .into_iter()
        .find(|candidate| fs::create_dir_all(candidate).is_ok())
}

fn resolve_native_gui_executable() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_NATIVE_GUI_EXE") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = if cfg!(windows) {
        "NetRuleRouter.exe"
    } else {
        "NetRuleRouter"
    };

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

        if let Ok(current_directory) = env::current_dir() {
            let cwd_candidate = current_directory
                .join("target")
                .join(profile)
                .join(executable_name);
            if cwd_candidate.exists() {
                return Some(cwd_candidate);
            }
        }
    }

    None
}

fn spawn_qml_line_reader<R>(reader: R, sender: mpsc::Sender<String>)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let buffered = BufReader::new(reader);
        for line in buffered.lines() {
            match line {
                Ok(line) => {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

pub fn write_qt_tray_context_file(
    runtime: &TrayRuntimeSnapshot,
    language: &str,
    preferences: &UiPreferences,
    icon_file_url: Option<String>,
) -> Result<PathBuf, String> {
    let locale_catalog = load_locale_catalog();
    let status_slug = runtime.status_kind.slug();
    let theme = resolve_theme(preferences.theme_mode);
    let context = TrayContextPayload {
        language: language.to_string(),
        locale_catalog: locale_catalog.clone(),
        status_key: format!("tray.status.{status_slug}"),
        status_accessibility_key: status_accessibility_key(runtime.status_kind),
        status_line: resolve_catalog_text(
            &locale_catalog,
            language,
            &format!("tray.status.{status_slug}"),
            runtime.status_line,
        ),
        status_accessibility_text: resolve_tray_status_accessibility_text(
            &locale_catalog,
            language,
            runtime.status_kind,
            runtime.status_line,
        ),
        route_primary_label: preferences.route_primary_label.clone(),
        route_secondary_label: preferences.route_secondary_label.clone(),
        icon_file_url,
        show_notifications: preferences.show_notifications,
        notify_suggestion_changes: preferences.notify_suggestion_changes,
        notify_block_notices: preferences.notify_block_notices,
        hide_block_notice_addresses: preferences.hide_block_notice_addresses,
        routing_detailed_mode: preferences.routing_detailed_mode,
        theme: TrayThemeContext {
            selected_mode: theme.selected_mode.slug().to_string(),
            effective_mode: theme.effective_mode.slug().to_string(),
            system_mode: theme.system_mode.slug().to_string(),
            system_mode_detected: theme.system_mode_detected,
        },
        primary_actions: to_action_context(&runtime.primary_actions, &locale_catalog, language),
        quick_actions: to_action_context(&runtime.quick_actions, &locale_catalog, language),
        platform_profile: nrr_shared::platform_profile::PlatformProfile::current(),
    };

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let file_path = env::temp_dir().join(format!(
        "nrr-tray-context-{}-{timestamp}.json",
        std::process::id()
    ));

    let payload = serde_json::to_string_pretty(&context)
        .map_err(|error| format!("Failed to serialize Qt tray context: {error}"))?;
    fs::write(&file_path, payload)
        .map_err(|error| format!("Failed to write Qt tray context file: {error}"))?;
    Ok(file_path)
}

fn emit_tray_context(output_path: &Path, options: TrayLaunchOptions) -> Result<(), String> {
    let shell = gui_shell_v1();
    let preferences = load_ui_preferences_with_fallback();
    let first_run_completed = options
        .first_run_completed_override
        .unwrap_or(preferences.first_run_completed);
    let effective_status_override = resolve_effective_status_override(options.status_override);
    let theme = resolve_theme(preferences.theme_mode);
    let runtime = tray_runtime_snapshot(
        &shell,
        first_run_completed,
        effective_status_override,
        theme.effective_mode,
        TrayServiceLink::Unknown,
    );
    let icon_file_url =
        resolve_asset_path(runtime.icon_asset_hint).map(|path| path_to_file_url(&path));
    let locale_catalog = load_locale_catalog();
    let status_slug = runtime.status_kind.slug();
    let context = TrayContextPayload {
        language: preferences.language.clone(),
        locale_catalog: locale_catalog.clone(),
        status_key: format!("tray.status.{status_slug}"),
        status_accessibility_key: status_accessibility_key(runtime.status_kind),
        status_line: resolve_catalog_text(
            &locale_catalog,
            &preferences.language,
            &format!("tray.status.{status_slug}"),
            runtime.status_line,
        ),
        status_accessibility_text: resolve_tray_status_accessibility_text(
            &locale_catalog,
            &preferences.language,
            runtime.status_kind,
            runtime.status_line,
        ),
        route_primary_label: preferences.route_primary_label.clone(),
        route_secondary_label: preferences.route_secondary_label.clone(),
        icon_file_url,
        show_notifications: preferences.show_notifications,
        notify_suggestion_changes: preferences.notify_suggestion_changes,
        notify_block_notices: preferences.notify_block_notices,
        hide_block_notice_addresses: preferences.hide_block_notice_addresses,
        routing_detailed_mode: preferences.routing_detailed_mode,
        theme: TrayThemeContext {
            selected_mode: theme.selected_mode.slug().to_string(),
            effective_mode: theme.effective_mode.slug().to_string(),
            system_mode: theme.system_mode.slug().to_string(),
            system_mode_detected: theme.system_mode_detected,
        },
        primary_actions: to_action_context(
            &runtime.primary_actions,
            &locale_catalog,
            &preferences.language,
        ),
        quick_actions: to_action_context(
            &runtime.quick_actions,
            &locale_catalog,
            &preferences.language,
        ),
        platform_profile: nrr_shared::platform_profile::PlatformProfile::current(),
    };

    let payload = serde_json::to_string_pretty(&context)
        .map_err(|error| format!("Failed to serialize Qt tray context: {error}"))?;
    fs::write(output_path, payload)
        .map_err(|error| format!("Failed to write tray context file: {error}"))?;
    Ok(())
}

fn to_action_context(
    actions: &[TrayActionRuntime],
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
) -> Vec<TrayActionContext> {
    actions
        .iter()
        .map(|item| TrayActionContext {
            id: item.action.id().to_string(),
            label: resolve_action_label(locale_catalog, language, item.action),
            enabled: item.availability.is_enabled(),
            accessible_description: resolve_action_accessibility_description(
                locale_catalog,
                language,
                item,
            ),
        })
        .collect()
}

fn action_label_key(action: AppAction) -> String {
    match action {
        AppAction::OpenSection(section) => format!("section.{}", section.slug()),
        _ => format!("action.{}", action.id()),
    }
}

fn action_accessibility_label_key(action: AppAction) -> String {
    format!("a11y.tray.action-label.{}", action.id())
}

fn action_accessibility_description_key(action: AppAction) -> String {
    format!("a11y.tray.action-description.{}", action.id())
}

fn setup_state_accessibility_note_key(setup: SetupActionAvailability) -> &'static str {
    match setup {
        SetupActionAvailability::Allowed => "a11y.tray.setup-state.allowed",
        SetupActionAvailability::SoftGuided => "a11y.tray.setup-state.soft-guided",
        SetupActionAvailability::BlockedUntilWizardCompletion => {
            "a11y.tray.setup-state.blocked-until-wizard-completion"
        }
    }
}

fn resolve_action_label(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    action: AppAction,
) -> String {
    let default_label = resolve_catalog_text(
        locale_catalog,
        language,
        &action_label_key(action),
        action.label(),
    );
    resolve_catalog_text(
        locale_catalog,
        language,
        &action_accessibility_label_key(action),
        &default_label,
    )
}

fn resolve_action_accessibility_description(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    action: &TrayActionRuntime,
) -> String {
    let localized_label = resolve_action_label(locale_catalog, language, action.action);
    let base = resolve_catalog_text(
        locale_catalog,
        language,
        &action_accessibility_description_key(action.action),
        &localized_label,
    );
    let setup_note = resolve_catalog_text(
        locale_catalog,
        language,
        setup_state_accessibility_note_key(action.setup_availability),
        "",
    );
    let preview_note = if action.availability.is_enabled() {
        String::new()
    } else {
        resolve_catalog_text(locale_catalog, language, "a11y.tray.preview-only-note", "")
    };
    [base, setup_note, preview_note]
        .into_iter()
        .filter(|chunk| !chunk.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn status_accessibility_key(status_kind: TrayStatusKind) -> String {
    format!("a11y.tray.status-text.{}", status_kind.slug())
}

fn resolve_tray_status_accessibility_text(
    locale_catalog: &BTreeMap<String, BTreeMap<String, String>>,
    language: &str,
    status_kind: TrayStatusKind,
    fallback: &str,
) -> String {
    resolve_catalog_text(
        locale_catalog,
        language,
        &status_accessibility_key(status_kind),
        fallback,
    )
}

fn build_qt_host_command(host_arguments: &[String]) -> Result<Command, String> {
    if let Some(qt_host_executable) = resolve_qt_host_executable() {
        let mut command = Command::new(qt_host_executable);
        command.args(host_arguments);
        return Ok(command);
    }

    let workspace_root = resolve_workspace_root()
        .ok_or_else(|| "Unable to resolve workspace root for launching nrr-qt-host.".to_string())?;
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root)
        .arg("run")
        .arg("-p")
        .arg("nrr-qt-host")
        .arg("--")
        .args(host_arguments);
    Ok(command)
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

    // Adjacent to the running binary works regardless of where target-dir
    // points (see comment in apps/desktop/gui/src/ui_surface.rs).
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

        if let Ok(current_directory) = env::current_dir() {
            let cwd_candidate = current_directory
                .join("target")
                .join(profile)
                .join(executable_name);
            if cwd_candidate.exists() {
                return Some(cwd_candidate);
            }
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

fn resolve_gui_backend_executable() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_GUI_BACKEND_EXE") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    if let Ok(legacy_path) = env::var("NRR_GUI_EXE") {
        let path = PathBuf::from(legacy_path);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = if cfg!(windows) {
        "NetRuleRouter.exe"
    } else {
        "NetRuleRouter"
    };

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

        if let Ok(current_directory) = env::current_dir() {
            let cwd_candidate = current_directory
                .join("target")
                .join(profile)
                .join(executable_name);
            if cwd_candidate.exists() {
                return Some(cwd_candidate);
            }
        }
    }

    None
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

    if let Ok(current_directory) = env::current_dir() {
        let cwd_candidate = current_directory.join("apps/desktop/qml/Main.qml");
        if cwd_candidate.exists() {
            return Some(cwd_candidate);
        }
    }

    None
}

fn resolve_qml_tray_path() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_QML_TRAY") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join("Tray.qml");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    let cwd_candidate = env::current_dir().ok()?.join("apps/desktop/qml/Tray.qml");
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    None
}

fn resolve_asset_path(relative_path: &str) -> Option<PathBuf> {
    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../")
        .join(relative_path);
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    let cwd_candidate = env::current_dir().ok()?.join(relative_path);
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    None
}

pub fn path_to_file_url(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_launch_options_arguments, parse_qml_action_marker, tray_action_from_id};
    use nrr_shared::AppAction;
    use nrr_ui_support::tray::TrayStatusKind;

    #[test]
    fn tray_parser_reads_first_run_and_status_flags() {
        let parsed = parse_launch_options_arguments([
            "--first-run=completed".to_string(),
            "--status=service-unavailable".to_string(),
        ]);

        assert_eq!(parsed.first_run_completed_override, Some(true));
        assert_eq!(
            parsed.status_override,
            Some(TrayStatusKind::ServiceUnavailable)
        );
    }

    /// The tray is the only surface that raises unsolicited windows, and its
    /// QML gate reads exactly this field. If the preference stopped reaching the
    /// context, "show notifications = off" would silently stop being honoured —
    /// so the plumbing is pinned here rather than left to the QML side.
    #[test]
    fn tray_context_carries_the_show_notifications_preference() {
        use nrr_ui_support::theme::resolve_theme;
        use nrr_ui_support::tray::tray_runtime_snapshot;
        use nrr_ui_support::ui_preferences::UiPreferences;

        let shell = nrr_shared::gui_shell_v1();
        for wanted in [true, false] {
            let preferences = UiPreferences {
                show_notifications: wanted,
                ..UiPreferences::default()
            };
            let theme = resolve_theme(preferences.theme_mode);
            let runtime = tray_runtime_snapshot(
                &shell,
                true,
                None,
                theme.effective_mode,
                nrr_ui_support::tray::TrayServiceLink::Unknown,
            );
            let path = super::write_qt_tray_context_file(
                &runtime,
                &preferences.language,
                &preferences,
                None,
            )
            .expect("context file is written to the temp dir");
            let raw = std::fs::read_to_string(&path).expect("context file is readable");
            let _ = std::fs::remove_file(&path);
            let parsed: serde_json::Value =
                serde_json::from_str(&raw).expect("context file is JSON");
            assert_eq!(
                parsed.get("showNotifications").and_then(|v| v.as_bool()),
                Some(wanted),
            );
        }
    }

    #[test]
    fn qml_action_marker_parser_extracts_action() {
        assert_eq!(
            parse_qml_action_marker("qml: NRR_TRAY_ACTION:rules"),
            Some("rules")
        );
        assert_eq!(parse_qml_action_marker("qml: unrelated"), None);
    }

    #[test]
    fn action_id_parser_supports_open_section_alias() {
        assert_eq!(
            tray_action_from_id("rules"),
            Some(AppAction::OpenSection(nrr_shared::AppSection::Rules))
        );
        assert_eq!(
            tray_action_from_id("open-main-window"),
            Some(AppAction::OpenMainWindow)
        );
        assert_eq!(tray_action_from_id("unknown-action"), None);
    }
}
