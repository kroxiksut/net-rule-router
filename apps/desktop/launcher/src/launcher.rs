//! Common launcher logic shared by `gui_main.rs` and `tray_main.rs`.
//!
//! The launcher is intentionally a thin orchestrator: acquire a
//! single-instance lock, emit the QML context JSON in-process, spawn exactly
//! one C++ Qt host child, stream its stdout/stderr while it runs (persisting
//! each `NRR_PREFS_JSON:` payload through the debounced writer), clean up
//! temporaries, and propagate the child exit code.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use nrr_application::backend_facade::{mock_scenario_from_env, tray_status_for_mock_scenario};
use nrr_desktop_gui::app_shell::{parse_launch_request_arguments, LaunchRequest};
use nrr_desktop_gui::ui_surface::{
    apply_qt_preferences_payload as apply_qt_payload, write_qt_context_file_at,
};
use nrr_desktop_tray::write_qt_tray_context_file;
use nrr_shared::{gui_shell_v1, ActivationSource, AppSection};
use nrr_ui_support::first_run::first_run_flow_snapshot;
use nrr_ui_support::theme::resolve_theme;
use nrr_ui_support::tray::{tray_runtime_snapshot, TrayServiceLink};
use nrr_ui_support::ui_preferences::{UiPreferences, UiPreferencesStore};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// stdout/stderr line marker emitted by Main.qml / Tray.qml on every
/// preference mutation. Each payload is a complete snapshot and is written
/// through to the store by [`crate::prefs_persistence`] while the session runs.
const PREFS_MARKER: &str = "NRR_PREFS_JSON:";

/// Per-user directory for the launcher's own diagnostic artefacts — its
/// `launcher-{surface}.log` files and the user-local copy of an exported
/// diagnostic archive. Shared by [`diag_log_path`] and
/// [`crate::archive_localize`]'s `user_archive_dir` so both always agree on
/// where the launcher logs live.
///
/// - **Windows**: `%TEMP%\NetRuleRouter` — transient per-user scratch. The
///   launcher is a GUI-subsystem binary with no console, so these files are the
///   only way to diagnose detached-spawn failures.
/// - **Linux / other unix**: `$XDG_STATE_HOME/netrulerouter`, falling back to
///   `~/.local/state/netrulerouter` per the XDG Base Directory spec. State data
///   (logs, history) belongs in `XDG_STATE_HOME` — deliberately NOT `/tmp`
///   (cleared on reboot, unfindable for a bug report) and NOT `~/.netrulerouter`
///   (a home dotfile, which XDG deprecates). A final fall back to the temp dir
///   keeps this total when neither `XDG_STATE_HOME` nor `HOME` is set.
pub(crate) fn user_diagnostics_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let mut dir = env::temp_dir();
        dir.push("NetRuleRouter");
        dir
    }
    #[cfg(not(windows))]
    {
        if let Some(base) = env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(base).join("netrulerouter");
        }
        if let Some(home) = env::var_os("HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("netrulerouter");
        }
        let mut dir = env::temp_dir();
        dir.push("netrulerouter");
        dir
    }
}

/// Path of the per-surface diagnostic log file,
/// `<user_diagnostics_dir>/launcher-{surface}.log`. Shared by [`diag_log`] and
/// [`rotate_session_log`] so both agree on the exact location.
fn diag_log_path(surface_tag: &str) -> PathBuf {
    let mut path = user_diagnostics_dir();
    path.push(format!("launcher-{surface_tag}.log"));
    path
}

/// Append a single diagnostic line to a per-surface log file under
/// [`user_diagnostics_dir`] (`launcher-{surface}.log`). The launcher is a
/// GUI-subsystem binary, so `eprintln!` is swallowed by the OS when there is
/// no parent console — file logging is the only way to diagnose problems in
/// detached-tray spawns (`QProcess::startDetached` from the C++ host) and
/// double-click launches.
pub(crate) fn diag_log(surface_tag: &str, message: &str) {
    let path = diag_log_path(surface_tag);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        // Best-effort timestamp using std::time. chrono is not a dep.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(file, "{ts} pid={} {message}", std::process::id());
    }
    // Mirror to the error stream — visible when launched from a console. Once
    // that stream has been pointed at this very file, echoing would only write
    // the same line twice, so it stops.
    if !crate::diag_stream::error_stream_is_captured() {
        eprintln!("{message}");
    }
}

/// Rotates a per-session log file so a fresh process only accumulates lines
/// from the current session: any existing file is renamed to a `.prev.log`
/// sibling (replacing an older `.prev.log`), and the next [`diag_log`] call
/// re-creates the original path empty via its own `create(true)` open.
///
/// Best-effort by design: a locked file (or any other I/O error) is silently
/// left in place and the caller keeps appending to it, same as before this
/// existed. Callers must only invoke this once the single-instance lock for
/// this surface is confirmed held by the CURRENT process — a duplicate
/// launch that hands activation off to the real primary must never rotate
/// (and thus never split) the primary's live log out from under it.
fn rotate_session_log(path: &Path) {
    if !path.is_file() {
        return;
    }
    let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
        return;
    };
    let prev_path = path.with_extension(format!("prev.{extension}"));
    let _ = fs::remove_file(&prev_path);
    let _ = fs::rename(path, &prev_path);
}

fn surface_tag(surface: LauncherSurface) -> &'static str {
    match surface {
        LauncherSurface::MainGui => "main",
        LauncherSurface::Tray => "tray",
    }
}

/// Which QML surface the launcher should bring up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LauncherSurface {
    /// `Main.qml` — the primary application window.
    MainGui,
    /// `Tray.qml` — the system-tray icon and context menu.
    Tray,
}

/// Configuration handed to [`run`] from the per-binary `main()`.
#[derive(Clone, Debug)]
pub struct LauncherConfig {
    pub surface: LauncherSurface,
    pub app_name: &'static str,
    pub app_user_model_id: &'static str,
    pub single_instance_key: &'static str,
}

impl LauncherConfig {
    pub fn main_gui() -> Self {
        Self {
            surface: LauncherSurface::MainGui,
            app_name: "NetRuleRouter",
            app_user_model_id: "NetRuleRouter.NetRuleRouter",
            single_instance_key: "gui-shell-v1",
        }
    }

    pub fn tray() -> Self {
        Self {
            surface: LauncherSurface::Tray,
            app_name: "NetRuleRouterTray",
            app_user_model_id: "NetRuleRouter.NetRuleRouterTray",
            single_instance_key: "tray-shell-v1",
        }
    }
}

/// Top-level launcher entry point.
pub fn run(config: LauncherConfig) -> ExitCode {
    let cli_args: Vec<String> = env::args().skip(1).collect();

    // Session elevation broker mode. When the dispatcher spawns this binary
    // elevated (via UAC) as the long-lived broker, we run ONLY the broker
    // accept loop and exit when the parent launcher dies: no GUI, no
    // single-instance lock, no tray, no preferences round-trip.
    if let Some(broker_args) = nrr_broker::BrokerServerArgs::from_cli(&cli_args) {
        return nrr_broker::run_broker_server(broker_args);
    }

    cleanup_temp_leftovers();
    // Once-a-day GitHub release check, main GUI only (the tray rides the
    // same cache). Detached background thread: never blocks launch, 5 s
    // network timeout, skipped while the last check is younger than 24 h.
    // The result surfaces as a notification on the next start (the context
    // is built before the fetch can finish — deliberate).
    if config.surface == LauncherSurface::MainGui {
        crate::update_check_fetch::spawn_daily_release_check();
    }
    let launch_request = parse_launch_request_arguments(cli_args);
    let (store, preferences) = load_preferences_with_fallback();

    match SingleInstanceGuard::acquire(config.single_instance_key) {
        Ok(Some(guard)) => run_primary(&config, store, preferences, launch_request, guard),
        Ok(None) => run_secondary(&config, &launch_request),
        Err(error) => {
            eprintln!("nrr-launcher: single-instance guard error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_primary(
    config: &LauncherConfig,
    store: Option<UiPreferencesStore>,
    preferences: UiPreferences,
    request: LaunchRequest,
    _guard: SingleInstanceGuard,
) -> ExitCode {
    let tag = surface_tag(config.surface);
    // The single-instance lock for `tag` is confirmed held by this process
    // (that's the only way `run_primary` gets called) — safe to rotate the
    // previous session's log out of the way before the first line lands.
    let log_path = diag_log_path(tag);
    rotate_session_log(&log_path);
    // Everything this process prints — including the crates it merely uses —
    // belongs in THIS surface's log, not in the log of whoever started it.
    // Done after the rotation so the redirected stream opens the fresh file.
    crate::diag_stream::capture_process_error_stream(&log_path);
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] surface={:?} request_source={:?} request_section={:?}",
            config.surface, request.source, request.section
        ),
    );
    let _ = &request;
    // Seed the archive raw-log cap from the stored preference so an export
    // issued before the first preferences round-trip already honours it.
    crate::archive_localize::set_service_log_budget_mib(preferences.archive_log_budget_mib);

    // Pick the BackendFacade implementation honoured by the cold-start
    // `write_qt_context_file_at`. NRR_BACKEND env var overrides the default
    // (`Ipc`); IPC mode probes the named pipe briefly and falls back to
    // mock + `Disconnected` on failure so the GUI can paint a status
    // banner without crashing.
    //
    // TODO: the IPC client spun up here is independent of the one
    // lazy-init'd in `rpc_dispatcher` on first request — that's two worker
    // threads against the same pipe. Consolidating them requires plumbing
    // the `Arc<dyn IpcClient>` out of the bundle and through the
    // dispatcher; tracked for a future cleanup.
    let backend_bundle =
        crate::backend_factory::create_backend(crate::backend_factory::BackendChoice::from_env());
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] backend choice={:?} status={:?}",
            backend_bundle.choice, backend_bundle.status
        ),
    );

    let context_file = match emit_context(config.surface, &preferences, &backend_bundle) {
        Ok(path) => path,
        Err(error) => {
            diag_log(
                tag,
                &format!("nrr-launcher: context emission failed: {error}"),
            );
            return ExitCode::FAILURE;
        }
    };
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] context_file={}",
            context_file.display()
        ),
    );

    let native_host = match resolve_native_host_executable() {
        Some(path) => path,
        None => {
            diag_log(
                tag,
                "nrr-launcher: `nrr_qt_native_host.exe` was not found. Build the \
                 `nrr-qt-host` crate (it owns the C++ Qt host build) and ensure \
                 the artefact is adjacent to this binary or pointed to by \
                 `NRR_QT_NATIVE_HOST_EXE`.",
            );
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] native_host={}",
            native_host.display()
        ),
    );

    let qml_path = match resolve_qml_path(config.surface) {
        Some(path) => path,
        None => {
            diag_log(
                tag,
                &format!(
                    "nrr-launcher: QML file for {:?} was not located.",
                    config.surface
                ),
            );
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };
    diag_log(
        tag,
        &format!("NRR_LAUNCHER[primary] qml_path={}", qml_path.display()),
    );

    let mut host_arguments = vec![
        format!("--qml={}", qml_path.display()),
        format!("--nrr-context-file={}", path_to_file_url(&context_file)),
    ];
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

    let mut command = Command::new(&native_host);
    command
        .args(&host_arguments)
        // stdin is piped so the launcher can write `NRR_IPC_RESPONSE:<json>`
        // lines back to the C++ host. The host's stdin reader thread
        // (`HostStdinReader` on the C++ side) consumes them and dispatches
        // per-correlation-id.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_no_window(&mut command);

    diag_log(
        tag,
        &format!("NRR_LAUNCHER[primary] spawning host args={host_arguments:?}"),
    );
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            diag_log(
                tag,
                &format!(
                    "nrr-launcher: failed to spawn `{}`: {error}",
                    native_host.display()
                ),
            );
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };
    diag_log(
        tag,
        &format!("NRR_LAUNCHER[primary] host pid={}", child.id()),
    );

    // Take child stdin so the dispatcher can write RPC responses back.
    // Wrapped in Arc<Mutex<_>> so concurrent dispatcher worker threads
    // serialise their writes.
    let child_stdin = match child.stdin.take() {
        Some(handle) => Some(std::sync::Arc::new(std::sync::Mutex::new(handle))),
        None => {
            diag_log(
                tag,
                "nrr-launcher: native host stdin was not captured; \
                 RPC dispatcher disabled this session",
            );
            None
        }
    };

    let stdout = match child.stdout.take() {
        Some(handle) => handle,
        None => {
            diag_log(tag, "nrr-launcher: native host stdout was not captured.");
            let _ = child.kill();
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };
    let stderr = match child.stderr.take() {
        Some(handle) => handle,
        None => {
            diag_log(tag, "nrr-launcher: native host stderr was not captured.");
            let _ = child.kill();
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };

    let (sender, receiver) = mpsc::channel::<String>();
    spawn_line_reader(stdout, sender.clone());
    spawn_line_reader(stderr, sender);

    // IPC client used by the RPC dispatcher. Lazy initialised on the first
    // NRR_IPC_REQUEST line so a session that never invokes a bridge method
    // does not pay the connect cost (named-pipe open + version negotiation).
    let mut ipc_client: Option<std::sync::Arc<dyn nrr_ipc_client::IpcClient>> = None;

    // Second connection reserved for long-running reads (diagnostic archive
    // export). A client serialises its calls on one pipe, so without this the
    // export blocked the 3 s health poll behind it and the GUI painted a
    // "Connecting to service" banner for the whole export. Created on first
    // use — a session that never exports an archive never opens it.
    let mut ipc_side_client: Option<std::sync::Arc<dyn nrr_ipc_client::IpcClient>> = None;

    // GUI-only sidecar SQLite handle. The actual SidecarDb is opened lazily
    // inside `handle_sidecar_request` on first `sidecar.*` request, so
    // launches that never touch metadata don't pay the file-open cost.
    let sidecar_handle = crate::sidecar_handlers::new_handle();

    // Session elevation broker handle. No process is spawned until the
    // first privileged mutation is rejected with `Forbidden`; the
    // dispatcher then relays through the broker (one UAC, reused for the
    // rest of the session). The broker dies with this launcher.
    let broker_handle = nrr_broker::new_handle();

    // Preference snapshots go to disk while the session runs, coalesced, so a
    // force-killed GUI loses at most the last fraction of a second of changes
    // instead of everything the user did.
    let mut prefs_writer =
        crate::prefs_persistence::DebouncedPreferenceWriter::new(tag, store, preferences);

    loop {
        let line = match prefs_writer.due_at() {
            Some(due) => {
                let wait = due.saturating_duration_since(Instant::now());
                match receiver.recv_timeout(wait) {
                    Ok(line) => line,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        prefs_writer.flush_if_due(Instant::now());
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            None => match receiver.recv() {
                Ok(line) => line,
                Err(_) => break,
            },
        };
        // Checked on every line, not just on the timeout branch: a chatty child
        // keeps the loop out of that branch and would otherwise starve a write
        // that is already due.
        prefs_writer.flush_if_due(Instant::now());
        if let Some(idx) = line.find(PREFS_MARKER) {
            let value = line[idx + PREFS_MARKER.len()..].trim();
            if !value.is_empty() {
                // The archive path needs one field of this payload and must not
                // race the debounced file write for it, so it gets an in-memory
                // copy as the payload goes by.
                crate::archive_localize::observe_prefs_payload(value);
                prefs_writer.observe(value, Instant::now());
            }
            continue;
        }
        // RPC bridge dispatch. Each request is handled on its own
        // short-lived worker thread (the IPC call blocks; we must not
        // stall PREFS_JSON or shutdown handling).
        if line.starts_with(nrr_shared::launcher_rpc::RPC_REQUEST_MARKER) {
            if let Some(stdin) = child_stdin.as_ref() {
                let side = crate::rpc_dispatcher::request_uses_side_channel(&line);
                if side && ipc_side_client.is_none() {
                    let client = nrr_ipc_client::NamedPipeIpcClient::start();
                    ipc_side_client = Some(std::sync::Arc::new(client)
                        as std::sync::Arc<dyn nrr_ipc_client::IpcClient>);
                }
                if !side && ipc_client.is_none() {
                    let client = nrr_ipc_client::NamedPipeIpcClient::start();
                    ipc_client = Some(std::sync::Arc::new(client)
                        as std::sync::Arc<dyn nrr_ipc_client::IpcClient>);
                }
                let selected = if side {
                    ipc_side_client.as_ref()
                } else {
                    ipc_client.as_ref()
                };
                if let Some(client) = selected {
                    let _ = crate::rpc_dispatcher::spawn_dispatch_worker(
                        line.clone(),
                        std::sync::Arc::clone(client),
                        std::sync::Arc::clone(&sidecar_handle),
                        std::sync::Arc::clone(&broker_handle),
                        std::sync::Arc::clone(stdin),
                        side,
                    );
                }
            } else {
                diag_log(
                    tag,
                    "nrr-launcher: dropping RPC request — child stdin unavailable",
                );
            }
            continue;
        }
        // Forward all other child output (Qt warnings/criticals, QML console.log,
        // diagnostic markers) to the per-surface log file (and to stderr for
        // console-launched runs). Needed so `NRR_HOST_*` host markers survive
        // when the launcher itself was spawned detached.
        diag_log(tag, &format!("child: {line}"));
    }
    diag_log(
        tag,
        "NRR_LAUNCHER[primary] child stdio drained (both pipes closed)",
    );
    // Nothing more can arrive on the channel, so the tail of the last burst is
    // written here rather than after the wait — which has its own failure exit.
    prefs_writer.flush();

    let exit_status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            diag_log(
                tag,
                &format!("nrr-launcher: failed to wait on native host: {error}"),
            );
            let _ = fs::remove_file(&context_file);
            return ExitCode::FAILURE;
        }
    };
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] child exited code={:?}",
            exit_status.code()
        ),
    );

    let _ = fs::remove_file(&context_file);

    let raw_code = exit_status.code().unwrap_or(1);
    let truncated: u8 = match u8::try_from(raw_code) {
        Ok(value) => value,
        Err(_) if raw_code == 0 => 0,
        Err(_) => 1,
    };
    ExitCode::from(truncated)
}

fn run_secondary(config: &LauncherConfig, request: &LaunchRequest) -> ExitCode {
    let tag = surface_tag(config.surface);
    // Same reasoning as the primary path, minus the rotation: this run appends
    // to the live log of the surface it belongs to instead of leaking its lines
    // into the log of the process that started it.
    crate::diag_stream::capture_process_error_stream(&diag_log_path(tag));
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[secondary] surface={:?} (single-instance lock held by another pid; \
             this run is a duplicate-launch handler)",
            config.surface
        ),
    );
    // For Tray surface a duplicate launch is a no-op — we cannot meaningfully
    // "activate" a tray icon and the running tray process already owns it.
    if matches!(config.surface, LauncherSurface::Tray) {
        diag_log(
            tag,
            "NRR_LAUNCHER[secondary] tray duplicate-launch: no-op (icon already owned by primary)",
        );
        return ExitCode::SUCCESS;
    }

    // For the main GUI, hand activation off to the running primary by writing
    // the request file the C++ Qt host polls via `takePendingGuiRequest`.
    // The host raises and activates the window and switches sections /
    // opens dialogs based on this payload, then deletes the file.
    if let Err(error) = write_activation_request_to_default_path(request) {
        eprintln!(
            "nrr-launcher: failed to write activation request for running \
             {} instance: {error}",
            config.app_name
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Path the C++ Qt host polls via `takePendingGuiRequest`.
pub fn default_activation_request_path() -> PathBuf {
    env::temp_dir()
        .join("NetRuleRouter")
        .join("gui-activation.json")
}

pub fn write_activation_request_to_default_path(request: &LaunchRequest) -> io::Result<()> {
    let path = default_activation_request_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_activation_request(request, &path)
}

pub fn write_activation_request(request: &LaunchRequest, path: &Path) -> io::Result<()> {
    let mut payload = serde_json::Map::new();
    payload.insert("activate".to_string(), serde_json::Value::Bool(true));
    if let Some(section) = request.section {
        payload.insert(
            "section".to_string(),
            serde_json::Value::String(section.to_string()),
        );
    }
    if request.open_about {
        payload.insert("openAbout".to_string(), serde_json::Value::Bool(true));
    }
    if request.open_license {
        payload.insert("openLicense".to_string(), serde_json::Value::Bool(true));
    }
    // `action` + `reason` carry intent beyond the section switch. Primary
    // GUI's `applyGuiActivationRequest` dispatches on `action`; absence
    // means "just a section switch".
    if let Some(action) = request.action.as_deref() {
        payload.insert(
            "action".to_string(),
            serde_json::Value::String(action.to_string()),
        );
    }
    if let Some(reason) = request.reason.as_deref() {
        payload.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }

    let serialized =
        serde_json::to_string(&serde_json::Value::Object(payload)).map_err(io::Error::other)?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
    file.write_all(serialized.as_bytes())?;
    Ok(())
}

// ─── Context emission ────────────────────────────────────────────────────

fn emit_context(
    surface: LauncherSurface,
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
) -> Result<PathBuf, String> {
    match surface {
        LauncherSurface::MainGui => emit_main_gui_context(preferences, backend_bundle),
        LauncherSurface::Tray => emit_tray_context(preferences, backend_bundle),
    }
}

fn emit_main_gui_context(
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
) -> Result<PathBuf, String> {
    let shell = gui_shell_v1();
    let request = default_launch_request();

    let section_to_open = if preferences.reopen_last_section_on_startup {
        preferences.last_opened_section
    } else {
        AppSection::InterfacesAndRoutes
    };

    let first_run = first_run_flow_snapshot(&shell, preferences.first_run_completed, None);

    let context_path = generate_temp_path("nrr-qt-context");
    write_qt_context_file_at(
        &context_path,
        &shell,
        section_to_open,
        ActivationSource::Menu,
        preferences.clone(),
        &first_run,
        &request,
        backend_bundle.facade.as_ref(),
        &backend_bundle.status,
    )?;

    Ok(context_path)
}

fn emit_tray_context(
    preferences: &UiPreferences,
    backend_bundle: &crate::backend_factory::BackendBundle,
) -> Result<PathBuf, String> {
    let shell = gui_shell_v1();
    let resolved_theme = resolve_theme(preferences.theme_mode);
    let mock_status_override = mock_scenario_from_env().and_then(tray_status_for_mock_scenario);
    // The cold-start probe already answered "can the service be talked to";
    // passing it on keeps the tray's first paint from asserting an enforcement
    // state nobody has looked at.
    let service_link = if backend_bundle.status.is_connected() {
        TrayServiceLink::Reachable
    } else {
        TrayServiceLink::Unavailable
    };
    let runtime = tray_runtime_snapshot(
        &shell,
        preferences.first_run_completed,
        mock_status_override,
        resolved_theme.effective_mode,
        service_link,
    );
    let icon_file_url = resolve_native_icon_path().as_deref().map(path_to_file_url);

    write_qt_tray_context_file(&runtime, &preferences.language, preferences, icon_file_url)
}

fn default_launch_request() -> LaunchRequest {
    LaunchRequest {
        source: ActivationSource::Menu,
        section: None,
        open_about: false,
        open_license: false,
        first_run_completed_override: None,
        first_run_scenario_override: None,
        action: None,
        reason: None,
    }
}

fn generate_temp_path(prefix: &str) -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    env::temp_dir().join(format!("{prefix}-{}-{timestamp}.json", std::process::id()))
}

/// Sweep `%TEMP%` for stale `nrr-*-context-*.json` files left behind when a
/// previous run was killed (kill-9, crash, fast machine shutdown). Graceful
/// exit already removes its own context file via `fs::remove_file(&context_file)`
/// in `run_primary`, but a force-killed process never gets there. Files older
/// than `LEFTOVER_MAX_AGE` are considered safely abandoned and deleted on
/// startup so `%TEMP%` does not grow unbounded over time.
fn cleanup_temp_leftovers() {
    const LEFTOVER_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(60 * 60);
    let temp_dir = env::temp_dir();
    let now = std::time::SystemTime::now();
    let Ok(entries) = fs::read_dir(&temp_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_name) = entry.file_name().into_string() else {
            continue;
        };
        let is_context_file = (file_name.starts_with("nrr-qt-context-")
            || file_name.starts_with("nrr-tray-context-"))
            && file_name.ends_with(".json");
        if !is_context_file {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let modified = metadata.modified().unwrap_or(now);
        if now.duration_since(modified).unwrap_or_default() < LEFTOVER_MAX_AGE {
            continue;
        }
        let _ = fs::remove_file(entry.path());
    }
}

// ─── Preferences round-trip ──────────────────────────────────────────────

fn load_preferences_with_fallback() -> (Option<UiPreferencesStore>, UiPreferences) {
    match UiPreferencesStore::managed_local() {
        Ok(store) => match store.load() {
            Ok(preferences) => (Some(store), preferences),
            Err(error) => {
                eprintln!(
                    "nrr-launcher: failed to load UI preferences from {}: {error}",
                    store.path().display()
                );
                (Some(store), UiPreferences::default())
            }
        },
        Err(error) => {
            eprintln!(
                "nrr-launcher: failed to initialise managed UI preferences storage, \
                 using defaults: {error}"
            );
            (None, UiPreferences::default())
        }
    }
}

/// What this surface should write back to the shared preferences file, or
/// `None` when it must not write at all.
///
/// Both user-facing binaries run this same launcher and persist to the SAME
/// file, each from the snapshot it loaded at its own start — and the tray never
/// emits a preferences payload. So a tray that outlives one main-window session
/// used to rewrite the whole file from a snapshot taken before that session,
/// discarding everything the window had recorded meanwhile. A surface that
/// never received a payload learned nothing and therefore has nothing to save:
/// the store keeps whatever the other process wrote.
pub fn preferences_to_persist(
    base: UiPreferences,
    latest_payload: Option<String>,
) -> Option<UiPreferences> {
    let payload = latest_payload?;
    match apply_qt_preferences_payload(&base, &payload) {
        Ok(updated) => Some(updated),
        Err(error) => {
            eprintln!("nrr-launcher: failed to apply prefs payload: {error}");
            // The payload is unusable, but the surface still emitted one, so
            // the baseline it started from is the honest thing to keep.
            Some(base)
        }
    }
}

/// Apply a Qt-side preferences payload over a baseline.
///
/// Delegates to the shared parser in `nrr-desktop-gui` so the launcher and
/// the legacy GUI bin agree on the canonical preferences round-trip.
pub fn apply_qt_preferences_payload(
    base: &UiPreferences,
    payload: &str,
) -> Result<UiPreferences, String> {
    apply_qt_payload(base.clone(), payload)
}

// ─── Native host resolution ──────────────────────────────────────────────

pub fn resolve_native_host_executable() -> Option<PathBuf> {
    if let Ok(explicit_path) = env::var("NRR_QT_NATIVE_HOST_EXE") {
        let path = PathBuf::from(explicit_path);
        if path.exists() {
            return Some(path);
        }
    }

    let executable_name = if cfg!(windows) {
        "nrr_qt_native_host.exe"
    } else {
        "nrr_qt_native_host"
    };

    if let Ok(current_executable) = env::current_exe() {
        if let Some(parent) = current_executable.parent() {
            let candidate = parent.join(executable_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // Dev-tree fallback: the absolute path baked at `nrr-qt-host` build time
    // (its `build.rs` emits `cargo:rustc-env=NRR_QT_NATIVE_HOST_EXE=...`).
    let baked = PathBuf::from(nrr_qt_host::NATIVE_HOST_EXE);
    if baked.exists() {
        return Some(baked);
    }

    None
}

// ─── QML / icon resolution ────────────────────────────────────────────────

fn resolve_qml_path(surface: LauncherSurface) -> Option<PathBuf> {
    let env_var = match surface {
        LauncherSurface::MainGui => "NRR_QML_MAIN",
        LauncherSurface::Tray => "NRR_QML_TRAY",
    };
    if let Ok(explicit) = env::var(env_var) {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }

    let relative = match surface {
        LauncherSurface::MainGui => "Main.qml",
        LauncherSurface::Tray => "Tray.qml",
    };

    // Installed / portable layout ships the QML tree beside the binary; the
    // second stem keeps a repository checkout working. Only then fall back to
    // CARGO_MANIFEST_DIR, which is baked at build time and therefore names a
    // directory that exists on the build machine alone.
    if let Some(found) = find_upward_from_executable(&[
        Path::new("qml").join(relative),
        Path::new("apps/desktop/qml").join(relative),
    ]) {
        return Some(found);
    }

    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../qml")
        .join(relative);
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }

    None
}

fn resolve_native_icon_path() -> Option<PathBuf> {
    if let Some(found) = find_upward_from_executable(&[PathBuf::from("assets/icons/app/app.ico")]) {
        return Some(found);
    }
    let manifest_candidate =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../assets/icons/app/app.ico");
    if manifest_candidate.exists() {
        return Some(manifest_candidate);
    }
    None
}

/// Levels walked upward from the executable — deep enough for a redirected
/// `target-dir` or a nested install tree, shallow enough to stay inside it.
const UPWARD_SEARCH_LEVELS: usize = 6;

fn find_upward_from_executable(relatives: &[PathBuf]) -> Option<PathBuf> {
    let executable = env::current_exe().ok()?;
    find_upward(executable.parent()?, relatives, UPWARD_SEARCH_LEVELS)
}

/// Nearest match wins: every relative path is tried at one level before
/// climbing, so a payload beside the binary is never shadowed by a copy above.
fn find_upward(start: &Path, relatives: &[PathBuf], levels: usize) -> Option<PathBuf> {
    let mut directory = Some(start);
    for _ in 0..levels {
        let current = directory?;
        for relative in relatives {
            let candidate = current.join(relative);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        directory = current.parent();
    }
    None
}

// ─── Subprocess plumbing ─────────────────────────────────────────────────

fn apply_no_window(command: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn spawn_line_reader<R>(reader: R, sender: mpsc::Sender<String>)
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

pub fn path_to_file_url(path: &Path) -> String {
    let normalized = path.to_string_lossy().replace('\\', "/");
    if normalized.starts_with('/') {
        format!("file://{normalized}")
    } else {
        format!("file:///{normalized}")
    }
}

// ─── Single-instance guard ───────────────────────────────────────────────

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

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.lock_path) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "nrr-launcher: failed to remove single-instance lock {}: {error}",
                    self.lock_path.display()
                );
            }
        }
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
    let mut command = Command::new("tasklist");
    command.args(["/FI", &filter, "/FO", "CSV", "/NH"]);
    apply_no_window(&mut command);

    match command.output() {
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
    let mut fields = trimmed.split(',');
    let _image_name = fields.next()?;
    let raw_pid = fields.next()?.trim().trim_matches('"');
    raw_pid.parse::<u32>().ok()
}

#[cfg(not(windows))]
fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // Unix single-instance lock cleanup: a live process still has a
    // `/proc/<pid>` entry on Linux. `/proc` needs no external crate; a
    // future macOS port (which lacks `/proc`) would swap this for a
    // `kill(pid, 0)` probe. Being wrong "alive" only delays reclaiming a stale
    // lock — it never steals one from a running instance.
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(test)]
mod tests {
    use super::{parse_pid_from_lock_content, rotate_session_log, LauncherConfig, LauncherSurface};
    use std::fs;

    #[test]
    fn pid_parser_extracts_value_from_lock_content() {
        assert_eq!(parse_pid_from_lock_content("pid=12345\n"), Some(12345));
        assert_eq!(parse_pid_from_lock_content("pid=abc\n"), None);
        assert_eq!(parse_pid_from_lock_content("key=value\n"), None);
    }

    #[test]
    fn launcher_config_main_gui_uses_canonical_names() {
        let config = LauncherConfig::main_gui();
        assert_eq!(config.surface, LauncherSurface::MainGui);
        assert_eq!(config.app_name, "NetRuleRouter");
        assert_eq!(config.app_user_model_id, "NetRuleRouter.NetRuleRouter");
        assert_eq!(config.single_instance_key, "gui-shell-v1");
    }

    #[test]
    fn launcher_config_tray_uses_canonical_names() {
        let config = LauncherConfig::tray();
        assert_eq!(config.surface, LauncherSurface::Tray);
        assert_eq!(config.app_name, "NetRuleRouterTray");
        assert_eq!(config.app_user_model_id, "NetRuleRouter.NetRuleRouterTray");
        assert_eq!(config.single_instance_key, "tray-shell-v1");
    }

    #[test]
    fn rotate_session_log_moves_existing_file_to_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("launcher-main.log");
        fs::write(&path, b"session one\n").expect("write log");

        rotate_session_log(&path);

        assert!(!path.exists(), "current log must be moved out of the way");
        let prev = dir.path().join("launcher-main.prev.log");
        assert_eq!(
            fs::read_to_string(&prev).expect("read prev"),
            "session one\n"
        );
    }

    #[test]
    fn rotate_session_log_replaces_an_older_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("launcher-main.log");
        let prev = dir.path().join("launcher-main.prev.log");
        fs::write(&prev, b"stale, two sessions ago\n").expect("write stale prev");
        fs::write(&path, b"session two\n").expect("write log");

        rotate_session_log(&path);

        assert_eq!(
            fs::read_to_string(&prev).expect("read prev"),
            "session two\n"
        );
    }

    #[test]
    fn rotate_session_log_is_a_noop_when_no_file_exists() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("launcher-main.log");

        // Must not create a file or panic on a first-ever launch.
        rotate_session_log(&path);

        assert!(!path.exists());
        assert!(!dir.path().join("launcher-main.prev.log").exists());
    }
}
