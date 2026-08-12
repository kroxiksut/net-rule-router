//! Windows service entrypoint binary.
//!
//! Modes (selected by argv\[1\]):
//!
//! - default (no arg, or invoked by SCM)  — connect to the Service
//!   Control Manager via `service_dispatcher::start`. If that returns
//!   `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` we fall back to console
//!   mode automatically (the canonical sign that the binary was launched
//!   from a shell rather than by SCM).
//! - `console` / `--console`  — run the runtime in the foreground with
//!   a Ctrl+C → `request_stop()` handler. For local dev / smoke tests.
//! - `install` / `--install`  — register the service with SCM
//!   (display name, description, autostart-delayed). Requires admin.
//! - `uninstall` / `--uninstall`  — unregister. Requires admin.
//! - `status` / `--status`  — print a one-shot orchestration banner
//!   and exit. Used by the smoke checklist.
//!
//! This binary delegates bootstrap, policy load, IPC server, and apply
//! control to the runtime body in
//! `nrr-service-runtime::lifecycle::run_runtime`.

use std::env;

use nrr_service_runtime::service_runtime_orchestration_snapshot;

#[cfg(windows)]
mod console_ctrl;
#[cfg(windows)]
mod power_scm;
#[cfg(windows)]
mod scm;
#[cfg(windows)]
mod service_config;

// Named-pipe IPC server modules. Cross-platform pieces (the in-memory
// transport) compile everywhere so unit tests run on CI without Windows;
// the actual pipe server is windows-only. The wire codec lives in
// `nrr-ipc-client` (single source of truth shared by client and server).
#[cfg(windows)]
mod named_pipe_acl;
#[cfg(windows)]
mod named_pipe_identity;
mod named_pipe_inmem;
#[cfg(windows)]
mod named_pipe_server;

// Production `SupervisedRuntimeDeps` builder. Called by both SCM mode
// (`scm.rs::run_scm_inner`) and console mode (`run_console`).
#[cfg(windows)]
mod runtime_deps;
mod stderr_capture;

fn main() -> std::process::ExitCode {
    // Publish this binary's semver to the ContractNegotiate handler so
    // the GUI's compatibility banner can render "Service X.Y.Z" in its
    // diagnostic line. Called BEFORE any handler runs so the first
    // handshake already sees the right value.
    nrr_service_runtime::set_service_binary_version(env!("CARGO_PKG_VERSION"));

    let args: Vec<String> = env::args().collect();
    let mode = args
        .get(1)
        .map(|s| s.trim_start_matches('-').to_lowercase())
        .unwrap_or_default();

    match mode.as_str() {
        #[cfg(windows)]
        "install" => match scm::install_service() {
            Ok(()) => {
                println!("Installed service '{}'.", nrr_service_runtime::SERVICE_NAME);
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("install failed: {e}");
                std::process::ExitCode::from(1)
            }
        },
        #[cfg(windows)]
        "update" => {
            let new_binary = args.get(2).cloned().unwrap_or_default();
            if new_binary.is_empty() {
                eprintln!("update requires <new-binary-path> as second argument");
                return std::process::ExitCode::from(1);
            }
            use nrr_service_runtime::UpdateConfig;
            match scm::update_service(&UpdateConfig::default_for(std::path::PathBuf::from(
                new_binary,
            ))) {
                Ok(outcome) => {
                    println!("Service drained for update.");
                    if let Some(bak) = outcome.state_db_backup {
                        println!("State DB backed up to: {}", bak.display());
                    }
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("update failed: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        // Elevated start-mode switch. Two SINGLE-TOKEN verbs, because the
        // session broker runs exactly one
        // whitelisted argv token (never a `<mode>` argument). `set-start-auto`
        // registers SERVICE_AUTO_START and revokes the console user's
        // SERVICE_START grant; `set-start-demand` grants the interactive console
        // user the targeted SERVICE_START right FIRST (so we never leave a
        // DemandStart service they can't start without UAC), then registers
        // SERVICE_DEMAND_START. See `apply_start_mode`.
        #[cfg(windows)]
        "set-start-auto" => apply_start_mode(nrr_service_runtime::ServiceStartMode::WithWindows),
        #[cfg(windows)]
        "set-start-demand" => apply_start_mode(nrr_service_runtime::ServiceStartMode::OnAppLaunch),
        // Read the current start mode (unelevated; SERVICE_QUERY_CONFIG is
        // open to authenticated users). Prints the slug
        // on stdout for the GUI to parse.
        #[cfg(windows)]
        "query-start-mode" => match service_config::query_start_mode() {
            Ok(mode) => {
                println!("{}", mode.slug());
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("query-start-mode failed: {e}");
                std::process::ExitCode::from(1)
            }
        },
        #[cfg(windows)]
        "uninstall" => {
            // Optional `--purge` flag switches from `keep_data()` (the default:
            // removing the service leaves %ProgramData%\NetRuleRouter\ alone)
            // to `purge_data()`, which is the application-removal path the
            // installer drives. Same spelling as the console's `--purge`.
            let purge = args.iter().skip(2).any(|a| {
                let lower = a.trim_start_matches('-').to_ascii_lowercase();
                lower == "purge"
            });
            use nrr_service_runtime::UninstallConfig;
            let config = if purge {
                UninstallConfig::purge_data()
            } else {
                UninstallConfig::keep_data()
            };
            match scm::uninstall_service_with_config(&config) {
                Ok(outcome) => {
                    println!(
                        "Uninstalled service '{}'.",
                        nrr_service_runtime::SERVICE_NAME
                    );
                    println!("  data_removed: {}", outcome.data_removed);
                    println!("  rule_files_preserved: {}", outcome.rule_files_preserved);
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("uninstall failed: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        #[cfg(windows)]
        "start" => match scm::start_service(15) {
            Ok(()) => {
                println!(
                    "Service '{}' start requested.",
                    nrr_service_runtime::SERVICE_NAME
                );
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("start failed: {e}");
                std::process::ExitCode::from(1)
            }
        },
        #[cfg(windows)]
        "stop" => match scm::stop_service(15) {
            Ok(()) => {
                println!("Service '{}' stopped.", nrr_service_runtime::SERVICE_NAME);
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("stop failed: {e}");
                std::process::ExitCode::from(1)
            }
        },
        // Restart in a SINGLE elevated process: stop (best-effort — OK if
        // already stopped), then start. The GUI dispatches this one command
        // so the user sees a single UAC prompt instead of two (one for stop
        // and one for start).
        #[cfg(windows)]
        "restart" => match scm::stop_service(15).and_then(|()| scm::start_service(15)) {
            Ok(()) => {
                println!("Service '{}' restarted.", nrr_service_runtime::SERVICE_NAME);
                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("restart failed: {e}");
                std::process::ExitCode::from(1)
            }
        },
        "status" => {
            print_status_banner();
            std::process::ExitCode::SUCCESS
        }
        // Disaster-recovery offline reset. Strips ALL NetRuleRouter WFP
        // filters (block AND permit), any leftover NRR-owned routes, and any
        // orphaned Mode-B NRPT/DNS-redirect rule WITHOUT the service running —
        // the escape hatch for a machine whose service crashed and left
        // orphaned state behind (a non-dynamic WFP session's block filters
        // survive `taskkill /F` until an explicit delete or reboot, and a
        // stranded NRPT redirect points all DNS at a dead listener, either of
        // which can lock the user off the network). Opens its own short-lived
        // WFP engine session, so it is safe to run when the service is
        // installed but stopped. Requires elevation. Backing the
        // `scripts/reset-network.ps1` wrapper.
        #[cfg(windows)]
        "cleanup" => runtime_deps::run_offline_reset(),
        // Explicit foreground runtime. ONLY a deliberate `console` verb runs
        // the runtime in the foreground (dev / smoke tests). It must stay
        // an explicit opt-in: a silent fallback here would turn a stale or
        // mis-routed invocation (e.g. an old binary that didn't recognise
        // `restart`) into a rogue second service process running until
        // killed.
        #[cfg(windows)]
        "console" => run_console(),
        #[cfg(not(windows))]
        "console" | "" => run_console(),
        // No argument: the canonical SCM-launched path. Connect to SCM and
        // block until SCM stops us. If there is NO SCM context (launched from
        // a shell or by another process), do NOT silently start the
        // foreground runtime — that is the footgun above. Error out; the
        // installed service is controlled via `start`/`stop`/`restart` (which
        // drive the SCM-managed process), and `console` runs a dev foreground.
        #[cfg(windows)]
        "" => match scm::run_under_scm() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(scm::ScmError::NotLaunchedBySCM) => {
                eprintln!(
                    "No SCM context and no `console` argument; refusing to run the \
                     foreground service runtime (this binary is managed by the Windows \
                     Service Control Manager). Use `start`/`stop`/`restart` to control \
                     the installed service, or pass `console` explicitly for a dev run."
                );
                std::process::ExitCode::from(2)
            }
            Err(e) => {
                eprintln!("SCM dispatch failed: {e}");
                std::process::ExitCode::from(2)
            }
        },
        // Any other (unknown) verb is a hard error — never a foreground run.
        _ => {
            eprintln!(
                "unknown subcommand `{mode}`; expected one of: \
                 install, uninstall, start, stop, restart, status, console, cleanup, \
                 set-start-auto, set-start-demand, query-start-mode, update"
            );
            std::process::ExitCode::from(2)
        }
    }
}

/// Apply a service start mode (shared by the `set-start-auto` /
/// `set-start-demand` verbs). For `OnAppLaunch` the targeted
/// `SERVICE_START` grant is added BEFORE the start-type flip, so the service is
/// never left DemandStart-without-grant (unstartable by the unprivileged
/// launcher). For `WithWindows` the grant is revoked best-effort afterwards.
#[cfg(windows)]
fn apply_start_mode(target: nrr_service_runtime::ServiceStartMode) -> std::process::ExitCode {
    use nrr_service_runtime::ServiceStartMode;
    let result = match target {
        ServiceStartMode::OnAppLaunch => service_config::grant_console_user_service_start()
            .and_then(|()| service_config::reconfigure_start_mode(target)),
        ServiceStartMode::WithWindows => {
            service_config::reconfigure_start_mode(target).map(|()| {
                // Best-effort: drop the now-unneeded SERVICE_START grant.
                if let Err(e) = service_config::revoke_console_user_service_start() {
                    eprintln!("warning: could not revoke SERVICE_START grant: {e}");
                }
            })
        }
    };
    match result {
        Ok(()) => {
            println!(
                "Service '{}' start mode set to '{}'.",
                nrr_service_runtime::SERVICE_NAME,
                target.slug()
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("set-start-mode failed: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

/// Opens a short-lived read-only connection to the state DB and asks the
/// storage layer whether the operator has saved
/// `verbose_logging = true`. Any failure (DB missing, file locked,
/// schema mismatch) degrades to `false` so the service falls back to
/// the canonical info-only NDJSON profile. Called BEFORE
/// `install_ndjson_tracing_*` so the initial `EnvFilter` directive
/// already matches the saved preference — no restart-to-apply gap
/// inside a single startup cycle.
pub(crate) fn read_verbose_logging_flag(state_db_path: &std::path::Path) -> bool {
    if !state_db_path.exists() {
        return false;
    }
    match rusqlite::Connection::open(state_db_path) {
        Ok(conn) => nrr_storage::service_stability_config::probe_verbose_logging(&conn),
        Err(_) => false,
    }
}

fn print_status_banner() {
    println!("{}", nrr_application::runtime_boot_banner("service"));
    println!("{}", nrr_application::runtime_boot_guard_message());
    let s = service_runtime_orchestration_snapshot();
    println!(
        "Service orchestration stub: lifecycle={} bootstrap={} policy={} ipc={} health={} \
         recovery={} privileged={} install_update={}",
        s.scm_lifecycle,
        s.bootstrap,
        s.policy_load,
        s.ipc_server,
        s.health_readiness,
        s.recovery,
        s.privileged_operations,
        s.install_update_hooks
    );
}

/// Foreground runtime for local dev. Installs a Ctrl+C handler that
/// flips the cooperative `StopToken`, then runs the supervised runtime
/// body the SCM mode also uses. Returns `ExitCode::SUCCESS` on graceful
/// shutdown.
fn run_console() -> std::process::ExitCode {
    use nrr_service_runtime::{
        install_ndjson_tracing_with_console_and_verbose, run_bootstrap, run_supervised_runtime,
        BootstrapConfig, ServiceController, ServiceRuntimeState, StopToken,
    };
    use nrr_storage::StorageProfile;
    use std::sync::Arc;

    print_status_banner();
    println!("Console mode — press Ctrl+C to stop.");
    eprintln!("[dbg] step=1 after-banner");

    struct ConsoleController;
    impl ServiceController for ConsoleController {
        fn report(&self, state: ServiceRuntimeState) {
            eprintln!("[service] state -> {state:?}");
        }
    }

    let stop = StopToken::new();
    eprintln!("[dbg] step=2 stop-token-created");

    // Real Win32 console-control handler installed via
    // `SetConsoleCtrlHandler`. The handler is a process-global
    // `extern "system" fn` that resolves the stop token through a
    // `OnceLock`; see `console_ctrl.rs`.
    #[cfg(windows)]
    {
        eprintln!("[dbg] step=3 before-console-ctrl-install");
        match console_ctrl::install(stop.clone()) {
            console_ctrl::InstallOutcome::Installed => {}
            console_ctrl::InstallOutcome::AlreadyInstalled => {
                eprintln!("warning: console-ctrl handler already installed; reusing prior wiring");
            }
            console_ctrl::InstallOutcome::RegistrationFailed => {
                eprintln!(
                    "warning: SetConsoleCtrlHandler registration failed; \
                     runtime will run until killed (use SCM stop or kill the process)"
                );
            }
        }
        eprintln!("[dbg] step=3b after-console-ctrl-install");
    }

    // Bootstrap first, then install the global NDJSON tracing subscriber
    // so operational `tracing::*` events are persisted from
    // here onward. Console mode uses the production storage profile so
    // dev smoke runs exercise the same topology and ACL paths real
    // installations use.
    eprintln!("[dbg] step=4 before-bootstrap-config");
    let cfg = BootstrapConfig::new(StorageProfile::ProductionService);
    eprintln!("[dbg] step=5 before-run-bootstrap");
    let artifacts = run_bootstrap(&cfg);
    eprintln!(
        "[dbg] step=6 after-run-bootstrap log_writer_some={}",
        artifacts.log_writer.is_some()
    );
    // Carries the live tracing-reload handle out of this block so it can
    // be threaded into `build_supervised_runtime_deps` below, letting a
    // mid-session verbose-logging Save apply without a service restart.
    // `None` when there's no log writer (degraded boot).
    let mut verbosity_handle: Option<nrr_service_runtime::TracingVerbosityHandle> = None;
    if let Some(writer) = artifacts.log_writer.as_ref() {
        // Probe the persisted verbose-logging flag BEFORE installing the
        // global tracing subscriber so the
        // EnvFilter directive is set correctly on the very first
        // event. Failure (DB missing, row missing, etc.) degrades to
        // false → canonical info-only.
        let verbose = read_verbose_logging_flag(&artifacts.topology.state_db_path);
        eprintln!("[dbg] step=7 before-install-ndjson-tracing verbose={verbose}");
        let (_outcome, handle) =
            install_ndjson_tracing_with_console_and_verbose(Arc::clone(writer), verbose);
        verbosity_handle = Some(handle);
        eprintln!("[dbg] step=8 after-install-ndjson-tracing");
        tracing::info!(
            target: "nrr::stability",
            verbose,
            "operational NDJSON verbosity",
        );
    } else {
        eprintln!(
            "warning: operational log writer unavailable; \
             tracing events will not be persisted to NDJSON this session"
        );
    }

    // Crash recovery hook. Runs BEFORE supervised runtime so a leftover
    // apply marker is observed and
    // acted on. `lkg_available` is probed live from
    // `RevisionsRepository::last_known_good`; outcomes that require
    // manual action propagate to `artifacts.report.blocking` so the
    // supervisor stays in `RecoveryRequired` instead of starting tasks.
    eprintln!("[dbg] step=9 before-probe-lkg");
    let lkg_available = nrr_service_runtime::probe_lkg_available(&artifacts.topology.state_db_path);
    eprintln!("[dbg] step=10 lkg_available={lkg_available}");
    let recovery_outcome = nrr_service_runtime::run_crash_recovery_on_startup(
        &artifacts.topology.data_dir,
        artifacts.audit_writer.clone(),
        Arc::new(nrr_service_runtime::ProductionIdGenerator::new()),
        lkg_available,
    );
    eprintln!("[dbg] step=11 after-crash-recovery");
    eprintln!("[service] crash-recovery outcome: {recovery_outcome:?}");
    // Mirror the SCM-mode info log from `scm.rs:195` so console-mode
    // dev sessions get the same NDJSON anchor for "service started OK".
    tracing::info!(
        target: "nrr::recovery",
        outcome = ?recovery_outcome,
        lkg_available,
        "crash recovery probe complete",
    );
    let mut artifacts = artifacts;
    if let nrr_service_runtime::CrashRecoveryOutcome::ManualActionRequired { .. }
    | nrr_service_runtime::CrashRecoveryOutcome::Aborted { .. } = recovery_outcome
    {
        // Block the runtime from going Running. The
        // supervisor's `run_supervised_runtime` checks
        // `artifacts.is_ready_to_run()` and walks straight to
        // `RecoveryRequired` when blocking is set.
        artifacts.report.blocking = true;
    }

    // Persist-on-stop — defensive standalone strip of any orphaned
    // block/fail-closed/kill-switch WFP filter a hard-killed prior instance
    // left behind. Runs before deps are built so a kill-switch is removed even
    // on a recovery-BLOCKED boot (where the orchestrator — and its own startup
    // strip — is never constructed). Idempotent on a healthy boot.
    #[cfg(windows)]
    runtime_deps::strip_orphaned_block_filters_standalone();

    // Supervised runtime: builds a HealthAggregator, ServiceSupervisor,
    // and spawns the canonical task set (adapter
    // monitor, health aggregator tick, IPC accept loop + watcher,
    // operation-results GC, diagnostics cleanup) before waiting on the
    // stop token.
    #[cfg(windows)]
    let deps = runtime_deps::build_supervised_runtime_deps(&artifacts, verbosity_handle);
    #[cfg(not(windows))]
    let deps: nrr_service_runtime::SupervisedRuntimeDeps = {
        let _ = verbosity_handle;
        unreachable!("console mode requires Windows for SupervisedRuntimeDeps construction")
    };
    let _reason = run_supervised_runtime(&ConsoleController, &stop, artifacts, deps);
    std::process::ExitCode::SUCCESS
}
