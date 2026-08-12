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
mod exit;
mod parse;
mod platform;
mod verbs;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use nrr_platform_api::service_control::{
    ServiceControlError, ServiceControlPort, ServiceInstallSpec, ServiceStatusReport,
    ServiceUninstallSpec,
};
use nrr_shared::product_identity::{BinaryRole, PRODUCT_NAME};

use parse::Command;

/// How long a lifecycle verb waits for the service to reach the requested
/// state. Matches what the application's own service controls allow.
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(15);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let exe = executable_name();

    let command = match parse::parse(&args) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("{err}");
            eprintln!("Run `{exe} help` for the list of verbs.");
            return ExitCode::from(exit::USAGE);
        }
    };

    ExitCode::from(run(command, &exe))
}

fn run(command: Command, exe: &str) -> u8 {
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
                    exit::SUCCESS
                }
                Err(err) => report_failure("install", &err, exe, "install"),
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
                    exit::SUCCESS
                }
                Err(err) => report_failure(
                    "uninstall",
                    &err,
                    exe,
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
            Err(err) => report_failure("start", &err, exe, "start"),
        }),
        Command::Stop => with_port(exe, "stop", |port| match port.stop(TRANSITION_TIMEOUT) {
            Ok(()) => {
                println!("Stopped.");
                exit::SUCCESS
            }
            Err(err) => report_failure("stop", &err, exe, "stop"),
        }),
        Command::Restart => with_port(exe, "restart", |port| {
            match port.restart(TRANSITION_TIMEOUT) {
                Ok(()) => {
                    println!("Restarted.");
                    exit::SUCCESS
                }
                Err(err) => report_failure("restart", &err, exe, "restart"),
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
    match report.start_mode {
        Some(mode) => println!("  starts:            {}", mode.slug()),
        None => println!("  starts:            unknown"),
    }
    match report.binary_path.as_ref() {
        Some(path) => println!("  binary:            {}", path.display()),
        None => println!("  binary:            unknown"),
    }
}

/// Print an actionable failure and pick its exit code. Access denied gets the
/// exact command to repeat, because "run it elevated" without the command is
/// how people end up retyping a verb wrong.
fn report_failure(operation: &str, err: &ServiceControlError, exe: &str, repeat_as: &str) -> u8 {
    match err {
        ServiceControlError::AccessDenied => {
            eprintln!("{operation} requires an elevated console.");
            eprintln!("Open a console as administrator and run: {exe} {repeat_as}");
        }
        ServiceControlError::NotInstalled => {
            eprintln!("The {PRODUCT_NAME} service is not installed.");
            eprintln!("Install it first: {exe} install");
        }
        other => eprintln!("{operation} failed: {other}"),
    }
    exit::for_error(err)
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
