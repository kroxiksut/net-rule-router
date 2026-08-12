//! `nrr-serviced` — the Linux system-service daemon entrypoint. Sibling of
//! `nrr-windows-service`; the systemd analog of the Windows SCM binary.
//!
//! Verbs (first positional argument, see [`cli`]):
//! - `run` — the daemon body (systemd `ExecStart` passes this).
//! - `install` / `uninstall` — write/remove the unit + logrotate drop-in and
//!   enable/disable the service via `systemctl`. Require root.
//! - `status` — print a one-shot banner and exit.
//! - `help` / no args — usage.
//!
//! Argv parsing lives in [`cli`] as a pure, unit-tested function; the OS verbs
//! (`run` / `install` / `uninstall`) are `#[cfg(target_os = "linux")]`. On a
//! non-Linux host (the Windows dev box) the crate still builds — those verbs
//! just print a "Linux only" message — so the workspace compiles everywhere.

mod cli;

#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod run;
#[cfg(target_os = "linux")]
mod unix_socket_server;

use std::process::ExitCode;

use cli::Command;

/// This daemon's own executable name, derived from the product identity so the
/// usage text can never disagree with what `install` writes into `ExecStart`.
const DAEMON_NAME: &str = nrr_shared::product_identity::BinaryRole::Service.unix_file_name();

fn main() -> ExitCode {
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
        #[cfg(not(target_os = "linux"))]
        Command::Run | Command::Install | Command::Uninstall => {
            eprintln!(
                "the `run`, `install` and `uninstall` verbs run only on Linux \
                 (this is the systemd daemon entrypoint)"
            );
            ExitCode::from(2)
        }
        Command::Unknown(verb) => {
            eprintln!(
                "unknown subcommand `{verb}`; expected one of: \
                 run, install, uninstall, status, help"
            );
            ExitCode::from(2)
        }
    }
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
         \x20   help         Show this help"
    );
}

fn print_status() {
    println!("{DAEMON_NAME} {}", env!("CARGO_PKG_VERSION"));
    #[cfg(target_os = "linux")]
    println!("platform: linux (systemd); enforcement backend: nftables (pending, block 19.2)");
    #[cfg(not(target_os = "linux"))]
    println!("platform: non-linux dev build — OS verbs are disabled");
}
