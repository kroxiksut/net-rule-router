//! Argv parsing for the Linux daemon — the analog of the `match mode.as_str()`
//! dispatch in `windows-service/main.rs`, but extracted as a PURE function so
//! the verb table is unit-tested without a systemd host. Mirrors the SCM
//! entrypoint's discipline: an unknown or missing verb NEVER silently starts
//! the daemon.

/// A parsed command-line verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `run` — the daemon body (systemd `ExecStart` passes this explicitly).
    Run,
    /// `install` — write the unit + logrotate drop-in and enable the service.
    Install,
    /// `uninstall` — disable + stop the service and remove its install files.
    Uninstall,
    /// `status` — print a one-shot banner and exit.
    Status,
    /// The unit's stop hook: undo the DNS redirect a dead daemon left behind.
    RestoreDns,
    /// Undo everything a dead daemon left on the machine: DNS, nft, routes.
    Cleanup,
    /// The same undo for a daemon that still runs: stopped first, killed when
    /// it hangs.
    StopAndCleanup,
    /// The unit's last word once the restarts are spent: DNS is handed back,
    /// and the policy goes too unless someone's leak protection keeps it.
    AfterCrash,
    /// `package-files <DIR>` — write the install footprint a distribution
    /// package ships under DIR, for the packaging script.
    PackageFiles,
    /// `help` / `--help` / no arguments — print usage.
    Help,
    /// Any unrecognised verb — a hard error, never a daemon start.
    Unknown(String),
}

/// Parse the first positional argument into a [`Command`].
///
/// Leading dashes are stripped and the verb is lower-cased, so `run`, `--run`
/// and `RUN` are equivalent. No arguments maps to [`Command::Help`] (safe:
/// systemd always passes an explicit `run`, so a bare shell invocation asking
/// for nothing gets usage, never a silent foreground daemon).
pub fn parse_command(args: &[String]) -> Command {
    let Some(first) = args.first() else {
        return Command::Help;
    };
    match first.trim_start_matches('-').to_ascii_lowercase().as_str() {
        "run" => Command::Run,
        "install" => Command::Install,
        "uninstall" => Command::Uninstall,
        "status" => Command::Status,
        "restore-dns" => Command::RestoreDns,
        "cleanup" => Command::Cleanup,
        "stop-and-cleanup" => Command::StopAndCleanup,
        "after-crash" => Command::AfterCrash,
        "package-files" => Command::PackageFiles,
        "help" | "h" | "" => Command::Help,
        other => Command::Unknown(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_command(&owned)
    }

    /// The unit's stop hook writes this word; a mismatch is a hook that
    /// silently restores nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_stop_hook_verb_is_the_one_the_unit_writes() {
        assert_eq!(
            parse(&[nrr_platform_linux::systemd::DAEMON_RESTORE_DNS_VERB]),
            Command::RestoreDns
        );
    }

    /// The console's `reset-network --stop-service` runs this word.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_console_stop_and_reset_verb_is_one_this_daemon_knows() {
        assert_eq!(
            parse(&[nrr_platform_api::service_control::STOP_AND_CLEANUP_VERB]),
            Command::StopAndCleanup
        );
    }

    /// The console's `reset-network` runs this word.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_console_reset_verb_is_one_this_daemon_knows() {
        assert_eq!(
            parse(&[nrr_platform_linux::systemd::DAEMON_CLEANUP_VERB]),
            Command::Cleanup
        );
    }

    #[test]
    fn no_arguments_is_help_never_a_silent_run() {
        assert_eq!(parse(&[]), Command::Help);
    }

    #[test]
    fn known_verbs_parse() {
        assert_eq!(parse(&["run"]), Command::Run);
        assert_eq!(parse(&["install"]), Command::Install);
        assert_eq!(parse(&["uninstall"]), Command::Uninstall);
        assert_eq!(parse(&["status"]), Command::Status);
        assert_eq!(
            parse(&["package-files", "/tmp/root"]),
            Command::PackageFiles
        );
        assert_eq!(parse(&["help"]), Command::Help);
    }

    #[test]
    fn dashes_and_case_are_normalised() {
        assert_eq!(parse(&["--run"]), Command::Run);
        assert_eq!(parse(&["--INSTALL"]), Command::Install);
        assert_eq!(parse(&["-h"]), Command::Help);
    }

    #[test]
    fn the_failure_hook_has_its_own_verb() {
        assert_eq!(parse(&["after-crash"]), Command::AfterCrash);
    }

    #[test]
    fn unknown_verb_is_reported_not_run() {
        assert_eq!(
            parse(&["frobnicate"]),
            Command::Unknown("frobnicate".to_string())
        );
    }

    #[test]
    fn only_the_first_positional_selects_the_verb() {
        // Extra args (e.g. future flags) do not change the verb.
        assert_eq!(parse(&["status", "--verbose"]), Command::Status);
    }
}
