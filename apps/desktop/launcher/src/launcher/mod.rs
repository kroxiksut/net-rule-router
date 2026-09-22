//! Common launcher logic shared by `gui_main.rs` and `tray_main.rs`.
//!
//! The launcher is intentionally a thin orchestrator: acquire a
//! single-instance lock, emit the QML context JSON in-process, spawn exactly
//! one C++ Qt host child, stream its stdout/stderr while it runs (persisting
//! each `NRR_PREFS_JSON:` payload through the debounced writer), clean up
//! temporaries, and propagate the child exit code.

use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nrr_shared::product_identity::BinaryRole;

use nrr_desktop_gui::app_shell::{parse_launch_request_arguments, LaunchRequest};
use nrr_desktop_gui::ui_surface::apply_qt_preferences_payload as apply_qt_payload;
use nrr_ui_support::ui_preferences::{SessionPreferences, UiPreferences, UiPreferencesStore};

mod child_process;
mod context;
mod diag_log;
mod resolve;
mod single_instance;

pub use child_process::path_to_file_url;
pub use context::cold_start_section;
pub(crate) use diag_log::{diag_log, user_diagnostics_dir};
pub use resolve::resolve_native_host_executable;
pub use single_instance::SingleInstanceGuard;

use child_process::{apply_no_window, spawn_line_reader};
use context::{cleanup_temp_leftovers, emit_context};
use diag_log::{diag_log_path, rotate_session_log, surface_tag};
use resolve::{resolve_native_icon_path, resolve_qml_path, sibling_service_binary};
use single_instance::{
    foreign_build_in_lock, is_process_alive, lock_file_path, parse_pid_from_lock_content,
};

/// stdout/stderr line marker emitted by Main.qml / Tray.qml on every
/// preference mutation. Each payload is a complete snapshot and is written
/// through to the store by [`crate::prefs_persistence`] while the session runs.
const PREFS_MARKER: &str = "NRR_PREFS_JSON:";

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
    /// Which binary this is, for diagnostics. Taken from the identity SSOT so
    /// a renamed role cannot leave the message naming a binary that is gone.
    pub app_name: &'static str,
    pub single_instance_key: &'static str,
}

impl LauncherConfig {
    pub fn main_gui() -> Self {
        Self {
            surface: LauncherSurface::MainGui,
            app_name: BinaryRole::Gui.host_file_name(),
            single_instance_key: "gui-shell-v1",
        }
    }

    pub fn tray() -> Self {
        Self {
            surface: LauncherSurface::Tray,
            app_name: BinaryRole::Tray.host_file_name(),
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

    install_system_theme_port();
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
        Ok(None) => match run_secondary(&config, &launch_request) {
            SecondaryOutcome::Handled(code) => code,
            // The lock owner never picked the activation up, so it cannot show a
            // window. Take the lock over rather than leave the user with a tray
            // click that does nothing.
            SecondaryOutcome::TakeOver => {
                match SingleInstanceGuard::reclaim(config.single_instance_key) {
                    Ok(guard) => run_primary(&config, store, preferences, launch_request, guard),
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                        // The owner is alive and still holds the OS claim; it is
                        // busy, not gone. A second primary here would be worse
                        // than no window.
                        eprintln!(
                            "nrr-launcher: {} is already running but did not answer;                              not starting a second instance",
                            config.single_instance_key
                        );
                        ExitCode::FAILURE
                    }
                    Err(error) => {
                        eprintln!(
                            "nrr-launcher: could not reclaim the single-instance lock: {error}"
                        );
                        ExitCode::FAILURE
                    }
                }
            }
        },
        Err(error) => {
            eprintln!("nrr-launcher: single-instance guard error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// What the duplicate-launch path decided. `TakeOver` means the recorded
/// primary proved unresponsive and this process should become the primary.
enum SecondaryOutcome {
    Handled(ExitCode),
    TakeOver,
}

fn run_primary(
    config: &LauncherConfig,
    store: Option<UiPreferencesStore>,
    preferences: UiPreferences,
    request: LaunchRequest,
    guard: SingleInstanceGuard,
) -> ExitCode {
    let tag = surface_tag(config.surface);
    // The single-instance lock for `tag` is confirmed held by this process
    // (that's the only way `run_primary` gets called) — safe to rotate the
    // previous session's log out of the way before the first line lands.
    let log_path = diag_log_path(tag);
    rotate_session_log(&log_path);
    // A request left behind by a duplicate launch nobody answered would
    // otherwise fire against this fresh session.
    if config.surface == LauncherSurface::MainGui {
        let _ = fs::remove_file(default_activation_request_path());
    }
    // Everything this process prints — including the crates it merely uses —
    // belongs in THIS surface's log, not in the log of whoever started it.
    // Done after the rotation so the redirected stream opens the fresh file.
    crate::diag_stream::capture_process_error_stream(&log_path);
    if let Some(stale_pid) = guard.removed_stale_pid {
        // Logged after rotation so it lands in the fresh log, not the one
        // just moved to `.prev.log`.
        diag_log(
            tag,
            &format!(
                "NRR_LAUNCHER[primary] removed stale single-instance lock held by pid={stale_pid}"
            ),
        );
    }
    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[primary] surface={:?} request_source={:?} request_section={:?}",
            config.surface, request.source, request.section
        ),
    );
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

    let context_file = match emit_context(config.surface, &preferences, &backend_bundle, &request) {
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
        // The host derives every lock and flag path from this. Passed rather
        // than recomputed there: the two sides agreed on Windows only because
        // both spelled `%TEMP%\NetRuleRouter`, and on Unix they would not —
        // this side uses the per-user runtime directory, not shared `/tmp`.
        format!(
            "--nrr-runtime-dir={}",
            nrr_platform_api::paths::user_runtime_dir().display()
        ),
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

    // In a cargo tree the Qt host lives deep under `target/<profile>/build/…`,
    // so the service binary is NOT its sibling and the host's own sibling-only
    // lookup finds nothing — leaving every service action in the GUI dead with
    // "Service binary not found" and the broker never spawned. This launcher IS
    // the service's sibling, so it can say where it is. Passed on every build:
    // the host is `RelWithDebInfo` in both profiles, so a debug-only hand-off
    // would have one end compiled out.
    if let Some(service_exe) = sibling_service_binary() {
        host_arguments.push(format!("--nrr-service-exe={}", service_exe.display()));
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

    // One service connection per lane (see `RpcLane`), each opened by the first
    // request that needs it: a session that never exports an archive never
    // pays for that pipe.
    let mut lane_clients = crate::rpc_dispatcher::LaneClients::default();

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
        // Anchored, like the RPC marker one file over. Searching anywhere in
        // the line meant any output that merely CONTAINED the marker — a rule
        // name echoed by a `console.log`, a truncated last line from a killed
        // host — was read as a preferences snapshot.
        if let Some(rest) = line.strip_prefix(PREFS_MARKER) {
            let value = rest.trim();
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
                let lane = crate::rpc_dispatcher::request_lane(&line);
                let (client, connect_budget) =
                    lane_clients.client_for(lane, Instant::now(), || {
                        std::sync::Arc::new(nrr_ipc_client::ServiceIpcClient::start())
                            as std::sync::Arc<dyn nrr_ipc_client::IpcClient>
                    });
                let _ = crate::rpc_dispatcher::spawn_dispatch_worker(
                    line.clone(),
                    client,
                    std::sync::Arc::clone(&sidecar_handle),
                    std::sync::Arc::clone(&broker_handle),
                    std::sync::Arc::clone(stdin),
                    connect_budget,
                );
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

/// How long a duplicate launch waits for the primary to consume the activation
/// file. The host polls it at 350 ms, so this is many chances to be seen.
const ACTIVATION_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// The same wait when the recorded owner process IS alive.
///
/// A primary only starts reading the activation file once its Qt host is up,
/// and a cold start spends seconds before that — longer than the short budget
/// above on its own. A double click on the shortcut therefore declared the
/// owner unresponsive while it was merely starting, and took the lock over: two
/// windows, two writers over one preferences file, two RPC dispatchers.
const ACTIVATION_ACK_TIMEOUT_OWNER_ALIVE: Duration = Duration::from_secs(30);
const ACTIVATION_ACK_POLL: Duration = Duration::from_millis(100);

/// Exit code for "a different build of this surface is already running".
/// Distinct from `FAILURE` so a script — or a developer reading `$?` after a
/// rebuild — can tell it apart from a launch that actually went wrong.
const EXIT_BUILD_MISMATCH: u8 = 4;

fn run_secondary(config: &LauncherConfig, request: &LaunchRequest) -> SecondaryOutcome {
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
    // A different build holding the lock is never a duplicate launch: it is the
    // previous build still running. Handing it the activation would raise ITS
    // window, which looks exactly like a rebuild that changed nothing — the
    // trap that cost a developer six hours. Say which build answered instead.
    if let Some((running, ours)) = foreign_build_in_lock(config.single_instance_key) {
        diag_log(
            tag,
            &format!(
                "NRR_LAUNCHER[secondary] ANOTHER BUILD of {} holds the single-instance lock; \
                 not activating it. running: [{running}] this: [{ours}]. \
                 Close the running instance before starting this one.",
                config.app_name
            ),
        );
        return SecondaryOutcome::Handled(ExitCode::from(EXIT_BUILD_MISMATCH));
    }

    // For Tray surface a duplicate launch is a no-op — we cannot meaningfully
    // "activate" a tray icon and the running tray process already owns it.
    if matches!(config.surface, LauncherSurface::Tray) {
        diag_log(
            tag,
            "NRR_LAUNCHER[secondary] tray duplicate-launch: no-op (icon already owned by primary)",
        );
        return SecondaryOutcome::Handled(ExitCode::SUCCESS);
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
        return SecondaryOutcome::Handled(ExitCode::FAILURE);
    }

    // The write is only half the handshake. A lock holder with no window left
    // (closed to tray, wedged, or a lock that merely looks held) never reads
    // the file, and the click silently does nothing — so wait for the file to
    // disappear and report which of the two happened.
    let activation_path = default_activation_request_path();
    let budget = activation_ack_budget(config.single_instance_key);
    let waited_from = Instant::now();
    while waited_from.elapsed() < budget {
        if !activation_path.exists() {
            diag_log(
                tag,
                &format!(
                    "NRR_LAUNCHER[secondary] activation consumed by primary after {} ms",
                    waited_from.elapsed().as_millis()
                ),
            );
            return SecondaryOutcome::Handled(ExitCode::SUCCESS);
        }
        std::thread::sleep(ACTIVATION_ACK_POLL);
    }

    diag_log(
        tag,
        &format!(
            "NRR_LAUNCHER[secondary] activation NOT consumed within {} ms — \
             the lock holder cannot show a window; taking the lock over",
            budget.as_millis()
        ),
    );
    // Our own request would otherwise be replayed by the GUI we are about to
    // start, on top of the request it already carries on its command line.
    let _ = fs::remove_file(&activation_path);
    SecondaryOutcome::TakeOver
}

/// Wires the OS appearance probe — light/dark and the high-contrast switch —
/// into `nrr-ui-support`, which is neutral and must not name an OS itself.
/// Without this the theme resolver answers "undetected", and the GUI shows its
/// fail-safe light theme knowing that is what it is.
fn install_system_theme_port() {
    #[cfg(windows)]
    nrr_ui_support::theme::install_system_theme_port(Box::new(
        nrr_platform_windows::system_theme::WindowsSystemTheme,
    ));
    #[cfg(target_os = "linux")]
    nrr_ui_support::theme::install_system_theme_port(Box::new(
        nrr_platform_linux::system_theme::LinuxSystemTheme,
    ));
}

/// How long to wait for the primary to answer, decided by whether it is still
/// there to answer at all.
fn activation_ack_budget(instance_key: &str) -> Duration {
    let owner_alive = fs::read_to_string(lock_file_path(instance_key))
        .ok()
        .and_then(|content| parse_pid_from_lock_content(&content))
        .is_some_and(is_process_alive);
    if owner_alive {
        ACTIVATION_ACK_TIMEOUT_OWNER_ALIVE
    } else {
        ACTIVATION_ACK_TIMEOUT
    }
}

/// Path the C++ Qt host polls via `takePendingGuiRequest`.
pub fn default_activation_request_path() -> PathBuf {
    nrr_platform_api::paths::user_runtime_dir().join("gui-activation.json")
}

pub fn write_activation_request_to_default_path(request: &LaunchRequest) -> io::Result<()> {
    // Through the guarded creator: the activation file is DISPATCHED as intent,
    // so the directory it lands in must be ours alone.
    nrr_platform_api::paths::ensure_user_runtime_dir()?;
    let path = default_activation_request_path();
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

// ─── Preferences round-trip ──────────────────────────────────────────────

fn load_preferences_with_fallback() -> (Option<UiPreferencesStore>, UiPreferences) {
    match UiPreferencesStore::managed_local() {
        Ok(store) => {
            let path = store.path().to_path_buf();
            match nrr_ui_support::ui_preferences::open_for_session(store) {
                SessionPreferences::Writable { store, preferences } => (Some(store), preferences),
                SessionPreferences::ReadOnly { preferences, error } => {
                    eprintln!(
                        "nrr-launcher: failed to load UI preferences from {}: {error}                          — running read-only this session so the file is not overwritten",
                        path.display()
                    );
                    (None, preferences)
                }
            }
        }
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
            // Nothing is written. The baseline is what THIS process read at
            // start-up, so persisting it discards whatever the other surface
            // recorded since — a payload we could not parse is a reason to know
            // less, never a reason to overwrite with an older picture.
            None
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

#[cfg(test)]
mod tests;
