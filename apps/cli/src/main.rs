//! `nrr-cli` — the administrative console.
//!
//! What it does: keeps the background service alive (install, start, stop,
//! status) and, when things go wrong, helps get the machine back. What it
//! deliberately does not do: touch routing policy. Rules, adapters and applying
//! changes live in the application; a console that could also apply policy
//! would be a second, unaudited way to change what the machine enforces.
//!
//! Output is English only: this is an operator surface, and operator surfaces
//! are not localised. The text is not an interface — only the verbs, the flags
//! and the exit codes are.

mod doctor;
mod elevate;
mod exit;
mod export;
mod logs;
mod parse;
mod platform;
mod verbs;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use nrr_platform_api::service_control::{
    ServiceControlError, ServiceControlPort, ServiceInstallSpec, ServiceStartMode,
    ServiceStatusReport, ServiceUninstallSpec,
};
use nrr_shared::product_identity::{BinaryRole, PRODUCT_NAME};

use parse::Command;

/// How long a lifecycle verb waits for the service to reach the requested
/// state. Matches what the application's own service controls allow.
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // An elevated copy of ourselves, running the real command on behalf of the
    // unelevated console that started us. Handled before parsing because it is
    // a process re-entry mode, not a verb — see `elevate`.
    if let Some(request) = elevate::relay_request(&args) {
        return ExitCode::from(elevate::run_relay(&request));
    }

    let exe = executable_name();
    let invocation = match parse::parse(&args) {
        Ok(invocation) => invocation,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("Run `{exe} help` for the list of verbs.");
            return ExitCode::from(exit::USAGE);
        }
    };

    // Decided before the command runs so the access-denied message can be
    // written for what happens next: "open an elevated console and type this
    // again" is wrong advice when a prompt is one line away.
    let relaunch = platform::privileged_relaunch();
    let ctx = Ctx {
        exe: &exe,
        elevation: elevate::plan(
            invocation.elevate,
            relaunch.is_some(),
            elevate::interactive(),
        ),
    };

    let code = run(invocation.command.clone(), &ctx);
    if code != exit::NEEDS_PRIVILEGE {
        return ExitCode::from(code);
    }
    // Only a verb that got as far as being refused for privilege is worth
    // re-running: elevation cannot help anything else, and asking anyway would
    // train the user to grant rights for unrelated failures.
    match elevate::retry(ctx.elevation, relaunch.as_deref(), &invocation.command) {
        Some(elevated) => ExitCode::from(elevated),
        None => ExitCode::from(code),
    }
}

/// What every verb needs to know about the invocation it is running under.
struct Ctx<'a> {
    /// How this console was invoked, for the commands it prints back.
    exe: &'a str,
    /// What may happen if the verb turns out to need administrator rights.
    elevation: elevate::ElevationPlan,
}

fn run(command: Command, ctx: &Ctx<'_>) -> u8 {
    let exe = ctx.exe;
    match command {
        Command::Help => {
            print!("{}", verbs::render_help(exe));
            exit::SUCCESS
        }
        Command::Version => {
            println!("{exe} {} ({PRODUCT_NAME})", env!("CARGO_PKG_VERSION"));
            exit::SUCCESS
        }
        Command::Status => with_port(exe, "status", |port| status(port.as_ref())),
        // Unlike every other verb, `diag doctor` runs even when this platform
        // has no service-manager implementation: "there is no implementation"
        // is one of the answers it exists to give.
        Command::DiagDoctor => {
            let port = platform::service_control();
            let facts = doctor::collect(port.as_deref());
            let findings = doctor::assess(&facts);
            print!("{}", doctor::render(&findings));
            doctor::exit_code(&findings, &facts.registration)
        }
        Command::DiagLogs { tail } => {
            logs::report(logs::read_tail(logs::log_directory(), tail), exe)
        }
        Command::DiagExport => export::run(exe),
        Command::ResetNetwork { confirmed } => reset_network(confirmed, ctx),
        Command::Install { start_mode } => with_port(exe, "install", |port| {
            let binary_path = match service_binary_path() {
                Ok(path) => path,
                Err(message) => {
                    eprintln!("{message}");
                    return exit::FAILED;
                }
            };
            let mut spec = ServiceInstallSpec::production_defaults(binary_path);
            spec.start_mode = start_mode;
            match port.install(&spec) {
                Ok(report) => {
                    println!("Installed the {PRODUCT_NAME} service.");
                    println!("  start mode:        {}", start_mode.slug());
                    println!("  binary:            {}", spec.binary_path.display());
                    println!(
                        "  crash recovery:    {}",
                        yes_no(report.recovery_configured)
                    );
                    match report.acl_applied {
                        Some(true) => println!("  data directory:    created and locked down"),
                        Some(false) => println!(
                            "  data directory:    created, but permissions could not be tightened"
                        ),
                        None => println!("  data directory:    left as it was"),
                    }
                    // Only worth a line when it went wrong: a registered source
                    // is invisible to the operator precisely because it works.
                    if report.event_source_registered == Some(false) {
                        println!(
                            "  system event log:  source not registered; lifecycle records will                              show without their description"
                        );
                    }
                    println!(
                        "  launcher may start: {}",
                        yes_no(apply_on_demand_grant(start_mode, &spec.binary_path))
                    );
                    exit::SUCCESS
                }
                Err(err) => report_failure("install", &err, ctx, "install"),
            }
        }),
        Command::Uninstall { purge } => with_port(exe, "uninstall", |port| {
            let spec = if purge {
                ServiceUninstallSpec::purge_data()
            } else {
                ServiceUninstallSpec::keep_data()
            };
            match port.uninstall(&spec) {
                Ok(report) => {
                    println!("Removed the {PRODUCT_NAME} service.");
                    println!(
                        "  service data:      {}",
                        if report.data_removed {
                            "deleted"
                        } else {
                            "kept"
                        }
                    );
                    println!("  your rule files:   kept");
                    // Removal is when a wedged install gets removed, so say out
                    // loud whether the machine was handed back clean: a leftover
                    // filter set or DNS redirect means no traffic and no product
                    // left to fix it.
                    match report.machine_state_cleared {
                        Some(true) => println!("  network state:     restored"),
                        Some(false) => println!(
                            "  network state:     NOT fully restored — run `{exe} \
reset-network` elevated, or reboot"
                        ),
                        None => {}
                    }
                    exit::SUCCESS
                }
                Err(err) => report_failure(
                    "uninstall",
                    &err,
                    ctx,
                    if purge {
                        "uninstall --purge"
                    } else {
                        "uninstall"
                    },
                ),
            }
        }),
        Command::Start => with_port(exe, "start", |port| match port.start(TRANSITION_TIMEOUT) {
            Ok(()) => {
                println!("Start requested.");
                exit::SUCCESS
            }
            Err(err) => report_failure("start", &err, ctx, "start"),
        }),
        Command::Stop => with_port(exe, "stop", |port| match port.stop(TRANSITION_TIMEOUT) {
            Ok(()) => {
                println!("Stopped.");
                exit::SUCCESS
            }
            Err(err) => report_failure("stop", &err, ctx, "stop"),
        }),
        Command::Restart => with_port(exe, "restart", |port| {
            match port.restart(TRANSITION_TIMEOUT) {
                Ok(()) => {
                    println!("Restarted.");
                    exit::SUCCESS
                }
                Err(err) => report_failure("restart", &err, ctx, "restart"),
            }
        }),
        // What `doctor` recommends when the registered binary is a different
        // copy than this one: remove the old registration (keeping the data)
        // and register the binary shipped next to this console.
        Command::Reinstall => with_port(exe, "reinstall", |port| {
            let binary_path = match service_binary_path() {
                Ok(path) => path,
                Err(message) => {
                    eprintln!("{message}");
                    return exit::FAILED;
                }
            };
            let previous = port.query().ok().flatten();
            let start_mode = previous.as_ref().and_then(|report| report.start_mode);
            if previous.is_some() {
                if let Err(err) = port.uninstall(&ServiceUninstallSpec::keep_data()) {
                    return report_failure("reinstall", &err, ctx, "reinstall");
                }
            }
            let mut spec = ServiceInstallSpec::production_defaults(binary_path);
            // Keep whatever start mode was registered; a re-registration is not
            // the place to silently change when the service starts.
            if let Some(mode) = start_mode {
                spec.start_mode = mode;
            }
            if let Err(err) = port.install(&spec) {
                eprintln!(
                    "The old registration was removed but the new one failed — \
                     the service is NOT registered right now."
                );
                return report_failure("reinstall", &err, ctx, "reinstall");
            }
            println!("Re-registered the {PRODUCT_NAME} service.");
            println!("  binary:            {}", spec.binary_path.display());
            println!("  start mode:        {}", spec.start_mode.slug());
            // The removal took the grant with the old registration, so an
            // on-demand service comes back unstartable by the launcher unless
            // it is re-issued here.
            println!(
                "  launcher may start: {}",
                yes_no(apply_on_demand_grant(spec.start_mode, &spec.binary_path))
            );
            match port.start(TRANSITION_TIMEOUT) {
                Ok(()) => {
                    println!("  service:           started");
                    exit::SUCCESS
                }
                Err(err) => report_failure("reinstall", &err, ctx, "start"),
            }
        }),
    }
}

/// Run `body` against the host's service manager, or refuse cleanly when this
/// platform has no implementation.
fn with_port(
    exe: &str,
    operation: &str,
    body: impl FnOnce(Box<dyn ServiceControlPort>) -> u8,
) -> u8 {
    match platform::service_control() {
        Some(port) => body(port),
        None => {
            eprintln!("`{exe} {operation}` is not supported on this platform yet.");
            exit::UNSUPPORTED
        }
    }
}

/// Report registration and run state. Answers without talking to the service:
/// this is the question people ask precisely when the service is not answering.
fn status(port: &dyn ServiceControlPort) -> u8 {
    match port.query() {
        Ok(Some(report)) => {
            print_status(&report);
            exit::SUCCESS
        }
        Ok(None) => {
            println!("{PRODUCT_NAME} service: not installed");
            exit::NOT_INSTALLED
        }
        Err(err) => {
            eprintln!("status failed: {err}");
            exit::for_error(&err)
        }
    }
}

fn print_status(report: &ServiceStatusReport) {
    println!("{PRODUCT_NAME} service: installed");
    println!("  state:             {}", report.run_state.slug());
    // The console and the service are shipped and replaced together, so this
    // console's version IS the installed version — with one exception, which
    // the next line names rather than leaving the operator to assume: replacing
    // the binary does not restart the process already loaded from it, so the
    // version that is REGISTERED and the version that is RUNNING can differ.
    println!("  version:           {}", env!("CARGO_PKG_VERSION"));
    if running_predates_binary(report) {
        println!("  running build:     older than the installed binary — restart to run it");
    }
    match report.start_mode {
        Some(mode) => println!("  starts:            {}", mode.slug()),
        None => println!("  starts:            unknown"),
    }
    match report.binary_path.as_ref() {
        Some(path) => println!("  binary:            {}", path.display()),
        None => println!("  binary:            unknown"),
    }
}

/// Give the interactive user the `SERVICE_START` grant an on-demand service
/// needs, by running the service binary's own start-mode verb.
///
/// Registering a service as demand-start says WHEN it may run, not WHO may
/// start it: without the grant the unelevated launcher can never bring it up,
/// which is the entire point of choosing on-demand. The grant is a DACL edit on
/// the service object, and the service binary already owns that code — this
/// console asks it rather than growing a second implementation that can drift
/// from the one the application uses.
///
/// Returns whether the grant is in place. `true` for start-with-Windows, where
/// no grant is wanted: the SCM starts it and nothing else needs the right.
fn apply_on_demand_grant(start_mode: ServiceStartMode, binary: &Path) -> bool {
    if start_mode != ServiceStartMode::OnAppLaunch {
        return true;
    }
    std::process::Command::new(binary)
        .arg("set-start-demand")
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether the running service process was started from an older file than the
/// one registered now.
///
/// Both facts have to be present to answer: a manager that reports no start
/// time, or a binary that cannot be stat'ed, means "not known", and the caller
/// says nothing rather than guessing in either direction.
fn running_predates_binary(report: &ServiceStatusReport) -> bool {
    let (Some(started), Some(path)) = (report.running_since, report.binary_path.as_ref()) else {
        return false;
    };
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .is_ok_and(|modified| modified > started)
}

/// Print an actionable failure and pick its exit code. Access denied gets the
/// exact command to repeat, because "run it elevated" without the command is
/// how people end up retyping a verb wrong — unless elevation is about to be
/// offered, in which case telling them to go and type it somewhere else is
/// advice for a situation that is not theirs.
fn report_failure(
    operation: &str,
    err: &ServiceControlError,
    ctx: &Ctx<'_>,
    repeat_as: &str,
) -> u8 {
    let exe = ctx.exe;
    match err {
        ServiceControlError::AccessDenied => {
            eprintln!("{operation} requires an elevated console.");
            if !ctx.elevation.acts() {
                eprintln!("Open a console as administrator and run: {exe} {repeat_as}");
            }
        }
        ServiceControlError::NotInstalled => {
            eprintln!("The {PRODUCT_NAME} service is not installed.");
            eprintln!("Install it first: {exe} install");
        }
        other => eprintln!("{operation} failed: {other}"),
    }
    exit::for_error(err)
}

/// Undo network state a crashed or hard-killed service left behind.
///
/// This console does not tear the state down itself — it runs the service
/// binary's own reset verb. That binary is what applied the state and is the
/// only thing that knows every piece of it; a second implementation here would
/// be a copy that drifts, and the copy that runs during an outage is the worst
/// place to discover the drift.
fn reset_network(confirmed: bool, ctx: &Ctx<'_>) -> u8 {
    let exe = ctx.exe;
    let Some(verb) = platform::offline_reset_verb() else {
        eprintln!("This build has no network reset.");
        eprintln!(
            "The service applies network state on this platform, but its binary carries no              reset verb yet, so there is nothing for this command to run."
        );
        eprintln!("Stop the service, and reboot if the machine is still cut off.");
        return exit::UNSUPPORTED;
    };
    if !confirmed {
        eprintln!("`{exe} reset-network` drops the network state the service applied:");
        eprintln!("  packet filters, the DNS redirect, and the routes it added.");
        eprintln!("Connections open right now may break. Re-run it as:");
        eprintln!("  {exe} reset-network --confirm");
        return exit::NOT_CONFIRMED;
    }
    let binary = match service_binary_path() {
        Ok(path) => path,
        Err(message) => {
            eprintln!("{message}");
            return exit::FAILED;
        }
    };
    // Inherited stdio: the service binary reports what it removed, and that
    // report is the useful part of running this at all.
    match std::process::Command::new(&binary).arg(verb).status() {
        Ok(status) if status.success() => exit::SUCCESS,
        // The reset verb answers with this console's own privilege code when
        // the engine refused it, so the answer arrives already classified: no
        // guessing from a generic failure, and the elevation offer in `main`
        // fires for the one command a locked-out user was told to run.
        Ok(status) if status.code() == Some(i32::from(exit::NEEDS_PRIVILEGE)) => {
            needs_elevation("reset-network", ctx, "reset-network --confirm")
        }
        Ok(status) => {
            eprintln!(
                "The service binary could not finish the reset ({}).",
                describe_exit(&status)
            );
            exit::FAILED
        }
        // Windows refuses to start a binary that demands elevation
        // (`ERROR_ELEVATION_REQUIRED`) rather than starting it and letting it
        // fail, so the refusal can arrive here instead of as an exit code.
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            needs_elevation("reset-network", ctx, "reset-network --confirm")
        }
        Err(err) => {
            eprintln!("could not run `{} {verb}`: {err}", binary.display());
            exit::FAILED
        }
    }
}

/// Report a refusal for privilege the same way every other verb does, and
/// return the code that lets `main` offer to re-run elevated.
///
/// The repeat command is suppressed when elevation is about to be offered:
/// telling someone to go and type it elsewhere is advice for a situation that
/// is not theirs.
fn needs_elevation(operation: &str, ctx: &Ctx<'_>, repeat_as: &str) -> u8 {
    eprintln!("{operation} requires an elevated console.");
    if !ctx.elevation.acts() {
        eprintln!(
            "Open a console as administrator and run: {} {repeat_as}",
            ctx.exe
        );
    }
    exit::NEEDS_PRIVILEGE
}

/// Human-readable form of a child process's exit status.
fn describe_exit(status: &std::process::ExitStatus) -> String {
    match status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated by a signal".to_string(),
    }
}

/// Absolute path of the service binary to register: the one sitting next to
/// this console. Both are shipped together, and deriving the name from the
/// product identity means a rename cannot leave the console pointing at a file
/// that no longer exists.
fn service_binary_path() -> Result<PathBuf, String> {
    let console = std::env::current_exe()
        .map_err(|e| format!("cannot determine this executable's location: {e}"))?;
    let directory = console
        .parent()
        .ok_or_else(|| "this executable has no parent directory".to_string())?;
    let candidate = directory.join(BinaryRole::Service.host_file_name());
    if candidate.exists() {
        Ok(candidate)
    } else {
        Err(format!(
            "cannot find the service binary `{}` next to this console ({}). \
             Install from the directory both were shipped in.",
            BinaryRole::Service.host_file_name(),
            directory.display()
        ))
    }
}

fn executable_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| BinaryRole::Console.host_file_name().to_string())
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "configured"
    } else {
        "not configured"
    }
}
