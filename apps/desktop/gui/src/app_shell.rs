use crate::accessibility::normalize_accessibility_preferences;
use crate::security::render_global_security_status;
use crate::settings::{load_preferences_with_fallback, persist_preferences};
use crate::summary::print_shell_summaries;
use crate::ui_surface::{
    apply_qt_preferences_payload, render_first_run_wizard, render_main_window_frame,
    render_section_shell, run_interactive_window,
};
use nrr_shared::{
    ActivationSource, AppSection, AppShellModel, FirstRunScenarioId, SetupActionAvailability,
};
use nrr_ui_support::first_run::{first_run_flow_snapshot, resolve_entry_section_for_first_run};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperCommand {
    EmitContext {
        output_path: PathBuf,
        request: LaunchRequest,
    },
    SavePreferences {
        input_path: PathBuf,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchRequest {
    pub source: ActivationSource,
    pub section: Option<AppSection>,
    pub open_about: bool,
    pub open_license: bool,
    pub first_run_completed_override: Option<bool>,
    pub first_run_scenario_override: Option<FirstRunScenarioId>,
    /// Secondary launchers can carry an opaque "action" slug that the
    /// primary GUI consumes via the `gui-activation.json` hand-off.
    /// Currently the only known slug is `"safe-disable"` (tray
    /// "Temporarily disable product impact" menu) which triggers a
    /// confirm-dialog flow in the primary instead of just a section
    /// switch. Backward compat: older launchers don't write this
    /// field; the primary GUI tolerates it being absent.
    pub action: Option<String>,
    /// Operator-provided justification accompanying `action`. Empty /
    /// `None` is acceptable — the primary GUI will prompt the user to
    /// fill it in if missing. Captured for audit regardless of where
    /// it originated.
    pub reason: Option<String>,
}

pub fn run_primary_instance(shell: &AppShellModel, request: LaunchRequest) {
    let (store, mut preferences) = load_preferences_with_fallback();
    normalize_accessibility_preferences(&mut preferences);

    let requested_section =
        request
            .section
            .unwrap_or(if preferences.reopen_last_section_on_startup {
                preferences.last_opened_section
            } else {
                AppSection::InterfacesAndRoutes
            });

    let first_run_completed = request
        .first_run_completed_override
        .unwrap_or(preferences.first_run_completed);
    preferences.first_run_completed = first_run_completed;
    let first_run = first_run_flow_snapshot(
        shell,
        first_run_completed,
        request.first_run_scenario_override,
    );

    let (section_to_open, availability) =
        resolve_entry_section_for_first_run(shell, requested_section, first_run_completed);

    if first_run.wizard_required {
        render_first_run_wizard(&first_run);
        if !matches!(availability, SetupActionAvailability::Allowed) {
            println!(
                "First-run guard: requested section '{}' is '{}' before wizard completion; opening '{}' first.",
                requested_section,
                availability.title(),
                section_to_open
            );
        }
    } else if request.first_run_completed_override == Some(true) && !preferences.first_run_completed
    {
        preferences.first_run_completed = true;
        println!("First-run state override: marked as completed for this launch.");
    } else if request.first_run_completed_override == Some(false) {
        println!(
            "First-run state override: wizard completion is required before unrestricted navigation."
        );
    }

    preferences.last_opened_section = section_to_open;
    persist_preferences(store.as_ref(), &preferences);

    print_shell_summaries(shell, preferences.clone(), store.as_ref());
    println!(
        "Opening section '{}' (source: {}).",
        section_to_open, request.source
    );
    render_main_window_frame(shell, section_to_open);
    render_global_security_status(shell);
    render_section_shell(shell, section_to_open, preferences.clone());

    if request.open_about {
        let about = nrr_application::about_window_info();
        println!(
            "About window: {} v{} | license={} | build_profile={} | toolchain={}",
            about.product_name,
            about.version,
            about.license,
            about.build_profile,
            about.rust_toolchain
        );
    }
    if request.open_license {
        println!("License window requested on startup.");
    }

    match run_interactive_window(
        *shell,
        section_to_open,
        request.source,
        preferences,
        first_run,
        &request,
    ) {
        Ok(updated_preferences) => {
            persist_preferences(store.as_ref(), &updated_preferences);
        }
        Err(error) => eprintln!("{error}"),
    }
}

pub fn run_secondary_launch(request: LaunchRequest) {
    let section = request.section.unwrap_or(AppSection::InterfacesAndRoutes);
    println!("GUI shell v1 is already running.");
    println!(
        "Secondary launch handled by existing instance: source={}, section={}",
        request.source, section
    );
    println!("IPC bridge to refocus the window is deferred to a later block.");
}

pub fn parse_launch_request_arguments<I>(arguments: I) -> LaunchRequest
where
    I: IntoIterator<Item = String>,
{
    let mut request = LaunchRequest {
        source: ActivationSource::Menu,
        section: None,
        open_about: false,
        open_license: false,
        first_run_completed_override: None,
        first_run_scenario_override: None,
        action: None,
        reason: None,
    };

    for argument in arguments {
        if argument == "--about" {
            request.open_about = true;
            continue;
        }
        if argument == "--license" {
            request.open_license = true;
            continue;
        }
        // `--action=<slug>` carries a secondary launch's intent beyond
        // a plain section switch. Today the only consumer is
        // `safe-disable`; unknown slugs are forwarded verbatim and
        // ignored by the primary GUI's dispatcher.
        if let Some(value) = argument.strip_prefix("--action=") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                request.action = Some(trimmed.to_string());
            }
            continue;
        }
        if let Some(value) = argument.strip_prefix("--reason=") {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                request.reason = Some(trimmed.to_string());
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--source=") {
            match value.parse::<ActivationSource>() {
                Ok(source) => request.source = source,
                Err(_) => eprintln!("Unknown --source value '{}'. Use menu|tray.", value),
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--section=") {
            match value.parse::<AppSection>() {
                Ok(section) => request.section = Some(section),
                Err(_) => eprintln!(
                    "Unknown --section value '{}'. Use interfaces-routes|rules|diagnostics|logs|settings.",
                    value
                ),
            }
            continue;
        }

        if let Some(value) = argument.strip_prefix("--first-run=") {
            request.first_run_completed_override = match value {
                "required" | "pending" => Some(false),
                "completed" | "done" | "skip" => Some(true),
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

        if let Some(value) = argument.strip_prefix("--scenario=") {
            request.first_run_scenario_override = parse_first_run_scenario(value);
            if request.first_run_scenario_override.is_none() {
                eprintln!(
                    "Unknown --scenario value '{}'. Use quick-start|guided-default.",
                    value
                );
            }
            continue;
        }

        eprintln!("Unknown GUI launch argument '{}'.", argument);
    }

    request
}

pub fn parse_helper_command(arguments: &[String]) -> Option<HelperCommand> {
    let mut helper_name = None::<String>;
    let mut output_path = None::<PathBuf>;
    let mut input_path = None::<PathBuf>;
    let mut request_arguments = Vec::new();

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
        if let Some(value) = argument.strip_prefix("--nrr-input=") {
            if !value.trim().is_empty() {
                input_path = Some(PathBuf::from(value.trim()));
            }
            continue;
        }
        request_arguments.push(argument.clone());
    }

    match helper_name.as_deref() {
        Some("emit-context") => Some(HelperCommand::EmitContext {
            output_path: output_path?,
            request: parse_launch_request_arguments(request_arguments),
        }),
        Some("save-prefs") => Some(HelperCommand::SavePreferences {
            input_path: input_path?,
        }),
        _ => None,
    }
}

pub fn run_helper_command(
    shell: &AppShellModel,
    helper_command: HelperCommand,
) -> Result<(), String> {
    match helper_command {
        HelperCommand::EmitContext {
            output_path,
            request,
        } => emit_context_for_qt(shell, request, &output_path),
        HelperCommand::SavePreferences { input_path } => {
            save_preferences_from_qt_payload(&input_path)
        }
    }
}

fn save_preferences_from_qt_payload(input_path: &Path) -> Result<(), String> {
    let payload = fs::read_to_string(input_path).map_err(|error| {
        format!(
            "Failed to read Qt preferences payload '{}': {error}",
            input_path.display()
        )
    })?;
    let (store, current_preferences) = load_preferences_with_fallback();
    let updated_preferences = apply_qt_preferences_payload(current_preferences, &payload)?;
    persist_preferences(store.as_ref(), &updated_preferences);
    Ok(())
}

fn emit_context_for_qt(
    shell: &AppShellModel,
    request: LaunchRequest,
    output_path: &Path,
) -> Result<(), String> {
    let (store, mut preferences) = load_preferences_with_fallback();
    normalize_accessibility_preferences(&mut preferences);

    let requested_section =
        request
            .section
            .unwrap_or(if preferences.reopen_last_section_on_startup {
                preferences.last_opened_section
            } else {
                AppSection::InterfacesAndRoutes
            });

    let first_run_completed = request
        .first_run_completed_override
        .unwrap_or(preferences.first_run_completed);
    preferences.first_run_completed = first_run_completed;
    let first_run = first_run_flow_snapshot(
        shell,
        first_run_completed,
        request.first_run_scenario_override,
    );

    let (section_to_open, _) =
        resolve_entry_section_for_first_run(shell, requested_section, first_run_completed);
    preferences.last_opened_section = section_to_open;
    persist_preferences(store.as_ref(), &preferences);

    // Legacy `--nrr-helper=emit-context` self-spawn path (kept for
    // compatibility but no longer used by the launcher). Pass a mock
    // backend and `Connected` status — the production launcher wires
    // the real `backend_factory::create_backend()` bundle through
    // `run()`.
    let backend: std::sync::Arc<dyn nrr_application::backend_facade::BackendFacade> =
        std::sync::Arc::new(nrr_application::backend_facade::MockBackendFacade);
    let backend_status = nrr_application::backend_facade::BackendConnectionStatus::Connected;
    crate::ui_surface::write_qt_context_file_at(
        output_path,
        shell,
        section_to_open,
        request.source,
        preferences,
        &first_run,
        &request,
        backend.as_ref(),
        &backend_status,
    )
}

pub fn parse_first_run_scenario(value: &str) -> Option<FirstRunScenarioId> {
    match value {
        "quick-start" | "quick" => Some(FirstRunScenarioId::QuickStart),
        "guided-default" | "guided" => Some(FirstRunScenarioId::GuidedDefault),
        _ => None,
    }
}

pub struct SingleInstanceGuard {
    lock_path: PathBuf,
    _lock_file: File,
}

impl SingleInstanceGuard {
    pub fn acquire(instance_key: &str) -> io::Result<Option<Self>> {
        let lock_directory = env::temp_dir().join("NetRuleRouter");
        fs::create_dir_all(&lock_directory)?;

        let lock_path = lock_directory.join(format!("{instance_key}.lock"));
        for attempt in 0..2 {
            match OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut lock_file) => {
                    writeln!(lock_file, "pid={}", std::process::id())?;
                    return Ok(Some(Self {
                        lock_path,
                        _lock_file: lock_file,
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if attempt == 0 && cleanup_stale_lock_file(&lock_path)? {
                        continue;
                    }
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }

        Ok(None)
    }
}

fn cleanup_stale_lock_file(lock_path: &Path) -> io::Result<bool> {
    let content = match fs::read_to_string(lock_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };

    let Some(pid) = parse_pid_from_lock_content(&content) else {
        return Ok(false);
    };
    if pid == std::process::id() {
        return Ok(false);
    }
    if is_process_alive(pid) {
        return Ok(false);
    }

    match fs::remove_file(lock_path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn parse_pid_from_lock_content(content: &str) -> Option<u32> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(raw_pid) = trimmed.strip_prefix("pid=") {
            if let Ok(parsed) = raw_pid.trim().parse::<u32>() {
                return Some(parsed);
            }
        }
    }
    None
}

#[cfg(windows)]
fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    let filter = format!("PID eq {pid}");
    let output = Command::new("tasklist")
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output();

    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(parse_tasklist_pid_from_csv_line)
            .any(|active_pid| active_pid == pid),
        Err(_) => false,
    }
}

#[cfg(windows)]
fn parse_tasklist_pid_from_csv_line(line: &str) -> Option<u32> {
    let trimmed = line.trim();
    if !trimmed.starts_with('"') {
        return None;
    }

    // tasklist /FO CSV /NH -> "Image Name","PID","Session Name","Session#","Mem Usage"
    let mut fields = trimmed.split(',');
    let _image_name = fields.next()?;
    let raw_pid = fields.next()?.trim().trim_matches('"');
    raw_pid.parse::<u32>().ok()
}

#[cfg(not(windows))]
fn is_process_alive(_pid: u32) -> bool {
    true
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.lock_path) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "Failed to remove GUI single-instance lock file '{}': {}",
                    self.lock_path.display(),
                    error
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_first_run_scenario, parse_launch_request_arguments, parse_pid_from_lock_content,
    };
    use nrr_shared::{ActivationSource, AppSection, FirstRunScenarioId};

    #[test]
    fn first_run_scenario_parser_accepts_supported_aliases() {
        assert_eq!(
            parse_first_run_scenario("quick-start"),
            Some(FirstRunScenarioId::QuickStart)
        );
        assert_eq!(
            parse_first_run_scenario("guided-default"),
            Some(FirstRunScenarioId::GuidedDefault)
        );
        assert_eq!(parse_first_run_scenario("unknown"), None);
    }

    #[test]
    fn launch_request_parser_maps_common_arguments() {
        let request = parse_launch_request_arguments([
            "--source=tray".to_string(),
            "--section=rules".to_string(),
            "--about".to_string(),
            "--first-run=required".to_string(),
            "--scenario=quick-start".to_string(),
        ]);

        assert_eq!(request.source, ActivationSource::Tray);
        assert_eq!(request.section, Some(AppSection::Rules));
        assert!(request.open_about);
        assert!(!request.open_license);
        assert_eq!(request.first_run_completed_override, Some(false));
        assert_eq!(
            request.first_run_scenario_override,
            Some(FirstRunScenarioId::QuickStart)
        );
    }

    #[test]
    fn launch_request_parser_accepts_action_and_reason() {
        let request = parse_launch_request_arguments([
            "--source=tray".to_string(),
            "--action=safe-disable".to_string(),
            "--reason=operator-test".to_string(),
        ]);

        assert_eq!(request.source, ActivationSource::Tray);
        assert_eq!(request.action.as_deref(), Some("safe-disable"));
        assert_eq!(request.reason.as_deref(), Some("operator-test"));
    }

    #[test]
    fn launch_request_parser_ignores_blank_action_and_reason() {
        let request =
            parse_launch_request_arguments(["--action= ".to_string(), "--reason=".to_string()]);

        assert_eq!(request.action, None);
        assert_eq!(request.reason, None);
    }

    #[test]
    fn pid_parser_extracts_value_from_lock_content() {
        assert_eq!(parse_pid_from_lock_content("pid=12345\n"), Some(12345));
        assert_eq!(parse_pid_from_lock_content("pid=abc\n"), None);
        assert_eq!(parse_pid_from_lock_content("key=value\n"), None);
    }
}
