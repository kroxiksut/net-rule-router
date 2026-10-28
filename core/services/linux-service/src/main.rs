//! `nrr-serviced` — the Linux system-service daemon entrypoint. Sibling of
//! `nrr-windows-service`; the systemd analog of the Windows SCM binary.
//!
//! Verbs (first positional argument, see [`cli`]):
//! - `run` — the daemon body (systemd `ExecStart` passes this).
//! - `install` / `uninstall` — write/remove the unit + logrotate drop-in and
//!   enable/disable the service via `systemctl`. Require root.
//! - `status` — print a one-shot banner and exit.
//! - `cleanup` — undo what a dead daemon left on the machine (see [`cleanup`]).
//! - `package-files <DIR>` — the unit and its companions a package ships.
//! - `help` / no args — usage.
//!
//! Argv parsing lives in [`cli`] as a pure, unit-tested function; the OS verbs
//! (`run` / `install` / `uninstall`) are `#[cfg(target_os = "linux")]`. On a
//! non-Linux host (the Windows dev box) the crate still builds — those verbs
//! just print a "Linux only" message — so the workspace compiles everywhere.

mod cleanup;
mod cli;

// The local DNS resolver over the machine's DNS mechanism.
#[cfg(target_os = "linux")]
mod dns_stack;
#[cfg(target_os = "linux")]
mod install;
// The provider bundle behind the daemon's full IPC surface.
#[cfg(target_os = "linux")]
mod ipc_deps;
#[cfg(target_os = "linux")]
mod run;
// The Linux counterpart of `windows-service/runtime_deps.rs`: assembles the
// dependency bundle the shared supervised runtime consumes.
#[cfg(target_os = "linux")]
mod runtime_deps;
#[cfg(target_os = "linux")]
mod unix_socket_server;

use std::process::ExitCode;

use cli::Command;

// A panic on foreign bytes is contained by unwinding; under abort one bad
// packet would stop the daemon and lift its protection.
#[cfg(panic = "abort")]
compile_error!("the service must be built with panic = \"unwind\"");

/// This daemon's own executable name, derived from the product identity so the
/// usage text can never disagree with what `install` writes into `ExecStart`.
const DAEMON_NAME: &str = nrr_shared::product_identity::BinaryRole::Service.unix_file_name();

fn main() -> ExitCode {
    // Before any handler runs, as on Windows: the handshake reports this
    // version, and the boot-timing card measures from this instant.
    #[cfg(target_os = "linux")]
    {
        nrr_service_runtime::set_service_binary_version(env!("CARGO_PKG_VERSION"));
        let _ = nrr_service_runtime::process_started_at_ms();
        nrr_service_runtime::install_throttled_panic_reports();
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    match cli::parse_command(&args) {
        Command::Help => {
            print_usage();
            ExitCode::SUCCESS
        }
        Command::Status => {
            print_status();
            ExitCode::SUCCESS
        }
        #[cfg(target_os = "linux")]
        Command::Run => run::run(),
        #[cfg(target_os = "linux")]
        Command::Install => install::install_service(),
        #[cfg(target_os = "linux")]
        Command::Uninstall => install::uninstall_service(),
        #[cfg(target_os = "linux")]
        Command::RestoreDns => restore_dns(),
        #[cfg(target_os = "linux")]
        Command::Cleanup => run_cleanup(false, true),
        #[cfg(target_os = "linux")]
        Command::StopAndCleanup => run_cleanup(true, true),
        #[cfg(target_os = "linux")]
        Command::AfterCrash => run_after_crash(),
        #[cfg(target_os = "linux")]
        Command::EarlyTable => run_early_table(),
        #[cfg(target_os = "linux")]
        Command::PackageFiles => install::write_package_files(args.get(1).map(String::as_str)),
        #[cfg(target_os = "linux")]
        Command::ProvisionCheck => provision_exit(
            nrr_service_runtime::provisioning::cli::run_check(args.get(1..).unwrap_or(&[])),
        ),
        #[cfg(target_os = "linux")]
        Command::ProvisionStage => provision_stage(args.get(1..).unwrap_or(&[])),
        #[cfg(not(target_os = "linux"))]
        Command::Run
        | Command::Install
        | Command::Uninstall
        | Command::RestoreDns
        | Command::Cleanup
        | Command::StopAndCleanup
        | Command::AfterCrash
        | Command::EarlyTable
        | Command::PackageFiles
        | Command::ProvisionCheck
        | Command::ProvisionStage => {
            eprintln!(
                "the `run`, `install`, `uninstall` and `cleanup` verbs run only on Linux \
                 (this is the systemd daemon entrypoint)"
            );
            ExitCode::from(2)
        }
        Command::Unknown(verb) => {
            eprintln!(
                "unknown subcommand `{verb}`; expected one of: \
                 run, install, uninstall, status, cleanup, package-files, \
                 provision-check, provision-stage, help"
            );
            ExitCode::from(2)
        }
    }
}

/// The stop hook. Quiet on success: it runs after every stop, most of them
/// clean, where there is nothing left to undo.
#[cfg(target_os = "linux")]
fn restore_dns() -> ExitCode {
    let Some(data_dir) = nrr_platform_api::paths::production_data_root() else {
        return ExitCode::SUCCESS;
    };
    match dns_stack::clear_dns_redirect(&data_dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("could not give the machine's DNS back: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// systemd's `OnFailure=` hook, run once the restarts are spent. Name
/// resolution is handed back whatever the settings; the policy goes too unless
/// someone's leak protection asked for blocking over leaking.
#[cfg(target_os = "linux")]
fn run_after_crash() -> ExitCode {
    use nrr_service_runtime::lifecycle_matrix::{
        after_crash_plan, leak_guard_armed_at, FilterTeardown, LifecycleInputs,
    };
    let Some(data_dir) = nrr_platform_api::paths::production_data_root() else {
        return ExitCode::SUCCESS;
    };
    let state_db =
        nrr_storage::resolve_storage_topology(&nrr_storage::StorageProfile::ProductionService)
            .map(|t| t.state_db_path)
            .unwrap_or_else(|_| data_dir.join("nrr_service_state.db"));
    let plan = after_crash_plan(LifecycleInputs {
        leak_guard_armed: leak_guard_armed_at(&state_db),
        keep_rule_routes_on_stop: false,
    });
    if plan.filters == FilterTeardown::RemoveAll {
        return run_cleanup(false, false);
    }
    let dns = dns_stack::clear_dns_redirect(&data_dir);
    println!("NetRuleRouter: the service stopped for good; name resolution handed back.");
    println!(
        "  Leak protection is on, so its filters and routes stay until the service runs again."
    );
    match dns {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("after-crash: could not give the machine's DNS back: {reason}");
            ExitCode::FAILURE
        }
    }
}

/// The early unit, before `network-pre.target`: the saved table goes up so no
/// session reaches the network before the daemon's first pass. Quiet when
/// nothing was saved.
#[cfg(target_os = "linux")]
fn run_early_table() -> ExitCode {
    let cli = nrr_platform_linux::nft_apply::NftCliEnforcement::new();
    match nrr_platform_linux::early_table::apply_saved(&cli) {
        Ok(true) => {
            println!("NetRuleRouter: the saved protection table is up until the service starts.");
            ExitCode::SUCCESS
        }
        Ok(false) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("early-table: the saved protection table could not be applied: {reason}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "linux")]
fn provision_exit((code, message): (u8, String)) -> ExitCode {
    if code == nrr_service_runtime::provisioning::exit::OK {
        println!("{message}");
    } else {
        eprintln!("{message}");
    }
    ExitCode::from(code)
}

/// Root only: the folder is root's, and the service refuses anything else.
#[cfg(target_os = "linux")]
fn provision_stage(args: &[String]) -> ExitCode {
    use nrr_service_runtime::provisioning::{cli, exit};
    if !nrr_platform_linux::elevation::running_as_root() {
        eprintln!("provision-stage needs root (sudo {DAEMON_NAME} provision-stage ...)");
        return ExitCode::from(exit::STAGE_FAILED);
    }
    let Some(dir) = nrr_platform_api::paths::production_provision_dir() else {
        return ExitCode::from(exit::STAGE_FAILED);
    };
    provision_exit(cli::run_stage(args, &dir))
}

/// Undo what a dead daemon left behind; [`cleanup`] owns the exit codes.
/// `revoke_overrides` for the person's own reset.
#[cfg(target_os = "linux")]
fn run_cleanup(stop_first: bool, revoke_overrides: bool) -> ExitCode {
    let outcome = cleanup::cleanup(
        &cleanup::SystemHost {
            data_dir: nrr_platform_api::paths::production_data_root(),
            revoke_overrides,
        },
        stop_first,
    );
    let (out, err) = cleanup::render(&outcome);
    print!("{out}");
    eprint!("{err}");
    ExitCode::from(cleanup::exit_code(&outcome))
}

fn print_usage() {
    let exe = DAEMON_NAME;
    let product = nrr_shared::product_identity::PRODUCT_NAME;
    println!(
        "{exe} — {product} Linux service\n\n\
         USAGE:\n    {exe} <VERB>\n\n\
         VERBS:\n\
         \x20   run          Run the daemon (used by the systemd unit's ExecStart)\n\
         \x20   install      Install and enable the systemd service (requires root)\n\
         \x20   uninstall    Disable and remove the systemd service (requires root)\n\
         \x20   status       Print a status banner and exit\n\
         \x20   cleanup      Undo the network state a stopped service left behind (requires root)\n\
         \x20   package-files DIR\n\
         \x20                Write the unit and the files beside it a package ships, under DIR\n\
         \x20   provision-check [--primary F] [--secondary F] [--settings F] [--secondary-unset direct|block]\n\
         \x20                Check files for an unattended install; nothing is written\n\
         \x20   provision-stage (the same options)\n\
         \x20                Check them and place them for the next service start (requires root)\n\
         \x20   help         Show this help"
    );
}

fn print_status() {
    println!("{DAEMON_NAME} {}", env!("CARGO_PKG_VERSION"));
    #[cfg(target_os = "linux")]
    {
        println!("platform: linux (systemd); enforcement backend: nftables");
        // Asked, not asserted: this banner is the first thing an operator runs,
        // and "nftables" alone says nothing about whether this host can use it.
        // Only root can ask; a refusal to an ordinary user is not the host's answer.
        if !nrr_platform_linux::elevation::running_as_root() {
            println!("nftables: not checked — the check needs root (sudo {DAEMON_NAME} status)");
            return;
        }
        match nrr_platform_linux::nft_backend::NftablesEnforcement::default().probe() {
            Ok(()) => println!("nftables: available"),
            Err(e) => println!("nftables: NOT available — {e}"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    println!("platform: non-linux dev build — OS verbs are disabled");
}
