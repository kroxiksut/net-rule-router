//! Linux privilege elevation via polkit `pkexec`.
//!
//! ## Two different questions, and only one of them is this module's
//!
//! Windows's GUI uses a session **elevation broker**: the launcher spawns an
//! *elevated copy of itself* (one UAC prompt) which then proxies many privileged
//! operations over an owner-bound pipe (`apps/desktop/broker`). That model is
//! Windows-shaped and its `call()` is hard-stubbed to `Unavailable` off Windows.
//!
//! Linux's privilege model is different: the privileged process is the **root
//! systemd service**, already running — the GUI does not spawn an elevated copy
//! of itself. polkit authorises whether the calling user MAY invoke a privileged
//! operation, either by gating the IPC call to the service or by launching a
//! small privileged helper via `pkexec`. Which of those the Linux launcher
//! ultimately uses is still a model decision, deferred until it is wired up.
//!
//! What IS settled and implemented here is the narrower question the
//! administrative console asks: *run this one command again with administrator
//! rights and wait for it*. That has a neutral port
//! ([`nrr_platform_api::elevation::PrivilegedRelaunchPort`]) and
//! [`PkexecRelaunch`] is its Linux answer.
//!
//! ## Why `pkexec` and not `sudo`
//!
//! `sudo` asks on the terminal, which is fine for a console and useless for a
//! desktop action; `pkexec` asks through the session's polkit agent and works
//! for both. Either way the child `execve`s in place and **keeps the caller's
//! terminal** — the asymmetry with Windows that the port makes explicit.
//!
//! Actually invoking `pkexec` needs a polkit agent (a desktop session), so the
//! spawn itself is exercised on real hardware; the argv builder and the exit-code
//! classification are pure and tested here.
//!
//! Portable `std` (the logic is exit-code arithmetic + `Command`), so it
//! compiles and its pure tests run on any host; the consumer selects it under
//! `#[cfg(target_os = "linux")]`.

use std::path::Path;
use std::process::Command;

use nrr_platform_api::elevation::{ElevatedRun, PrivilegedRelaunchPort};

/// The polkit CLI used to run a helper with elevated privileges. Shows the
/// polkit authentication dialog, then execs the helper as root.
pub const PKEXEC_PROGRAM: &str = "pkexec";

/// Outcome of an elevation attempt. Mirrors the semantics of the Windows
/// broker's `SpawnOutcome` so a future neutral seam can unify them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElevationOutcome {
    /// polkit authorized and the helper was launched (its own exit code is the
    /// helper's business, not an elevation failure).
    Launched,
    /// The user dismissed the polkit dialog, or is not authorized for the
    /// action. Surface a localizable "needs administrator".
    Declined,
    /// Local plumbing failure — `pkexec` missing, or the helper could not be
    /// spawned.
    Failed(String),
}

/// Builds the argv for launching `helper` (with `args`) under `pkexec`.
///
/// Unlike the Windows broker's PowerShell path, there is NO shell string and
/// therefore no quoting/injection surface: `pkexec` `execve`s the helper
/// directly, so each element is passed as a distinct argv entry. The returned
/// vector is `[helper, args...]` — the arguments to `Command::new(PKEXEC_PROGRAM)`.
pub fn pkexec_argv(helper: &Path, args: &[String]) -> Vec<String> {
    let mut argv = Vec::with_capacity(1 + args.len());
    argv.push(helper.to_string_lossy().into_owned());
    argv.extend(args.iter().cloned());
    argv
}

/// Classifies a finished `pkexec` process's exit status into an
/// [`ElevationOutcome`], per pkexec(1):
/// - `127` — not authorized / authentication could not be obtained → the user
///   declined or lacks rights → [`ElevationOutcome::Declined`].
/// - `126` — the helper could not be found or spawned → plumbing →
///   [`ElevationOutcome::Failed`].
/// - any other code (including the helper's own `0` / non-zero) — polkit
///   authorized and ran the helper → [`ElevationOutcome::Launched`].
/// - `None` (terminated by a signal) → [`ElevationOutcome::Failed`].
pub fn classify_pkexec_exit(code: Option<i32>) -> ElevationOutcome {
    match code {
        Some(127) => ElevationOutcome::Declined,
        Some(126) => {
            ElevationOutcome::Failed("pkexec could not spawn the helper (126)".to_string())
        }
        Some(_) => ElevationOutcome::Launched,
        None => ElevationOutcome::Failed("pkexec was terminated by a signal".to_string()),
    }
}

/// Runs `helper` (with `args`) under `pkexec` and classifies the outcome. Thin
/// wrapper over [`pkexec_argv`] + [`classify_pkexec_exit`]; requires a polkit
/// agent (a desktop session), so it is exercised on real hardware, not in unit
/// tests.
pub fn run_pkexec(helper: &Path, args: &[String]) -> ElevationOutcome {
    let argv = pkexec_argv(helper, args);
    match Command::new(PKEXEC_PROGRAM).args(&argv).status() {
        Ok(status) => classify_pkexec_exit(status.code()),
        Err(e) => ElevationOutcome::Failed(format!("spawn {PKEXEC_PROGRAM}: {e}")),
    }
}

/// The Linux answer to "run this one command again with administrator rights".
#[derive(Debug, Default, Clone, Copy)]
pub struct PkexecRelaunch;

impl PkexecRelaunch {
    pub const fn new() -> Self {
        Self
    }
}

impl PrivilegedRelaunchPort for PkexecRelaunch {
    /// Always: `pkexec` `execve`s the helper with this process's stdin, stdout
    /// and stderr, so the child writes straight into the terminal the user is
    /// looking at. Nothing has to carry its output back.
    fn inherits_terminal(&self) -> bool {
        true
    }

    fn relaunch_and_wait(&self, program: &Path, args: &[String]) -> ElevatedRun {
        let argv = pkexec_argv(program, args);
        match Command::new(PKEXEC_PROGRAM).args(&argv).status() {
            // The child's code and pkexec's own share one channel — 126 and 127
            // are pkexec's, everything else is the child's. Documented on
            // `classify_pkexec_exit`; the console's codes stay clear of both.
            Ok(status) => match classify_pkexec_exit(status.code()) {
                ElevationOutcome::Launched => ElevatedRun::Completed {
                    exit_code: status.code().and_then(|c| u8::try_from(c).ok()),
                },
                ElevationOutcome::Declined => ElevatedRun::Declined,
                ElevationOutcome::Failed(message) => ElevatedRun::Failed(message),
            },
            Err(e) => ElevatedRun::Failed(format!("spawn {PKEXEC_PROGRAM}: {e}")),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn pkexec_argv_puts_helper_first_then_args() {
        let helper = PathBuf::from("/usr/lib/netrulerouter/nrr-privileged-helper");
        let args = vec!["--apply".to_string(), "rev-42".to_string()];
        assert_eq!(
            pkexec_argv(&helper, &args),
            vec![
                "/usr/lib/netrulerouter/nrr-privileged-helper".to_string(),
                "--apply".to_string(),
                "rev-42".to_string(),
            ]
        );
    }

    #[test]
    fn pkexec_argv_with_no_args_is_just_the_helper() {
        let helper = PathBuf::from("/usr/bin/nrr-helper");
        assert_eq!(
            pkexec_argv(&helper, &[]),
            vec!["/usr/bin/nrr-helper".to_string()]
        );
    }

    #[test]
    fn exit_127_is_declined() {
        assert_eq!(classify_pkexec_exit(Some(127)), ElevationOutcome::Declined);
    }

    #[test]
    fn exit_126_is_failed_plumbing() {
        assert!(matches!(
            classify_pkexec_exit(Some(126)),
            ElevationOutcome::Failed(_)
        ));
    }

    #[test]
    fn helper_own_exit_codes_count_as_launched() {
        // 0 and the helper's own non-zero codes both mean polkit authorized and
        // ran the helper — elevation itself succeeded.
        assert_eq!(classify_pkexec_exit(Some(0)), ElevationOutcome::Launched);
        assert_eq!(classify_pkexec_exit(Some(1)), ElevationOutcome::Launched);
        assert_eq!(classify_pkexec_exit(Some(42)), ElevationOutcome::Launched);
    }

    #[test]
    fn signal_termination_is_failed() {
        assert!(matches!(
            classify_pkexec_exit(None),
            ElevationOutcome::Failed(_)
        ));
    }

    #[test]
    fn this_mechanism_keeps_the_callers_terminal() {
        // The whole output-handling branch of the console hangs off this
        // answer: on Linux the elevated child has already printed to the user's
        // terminal, so printing anything again would double it.
        assert!(PkexecRelaunch::new().inherits_terminal());
    }
}
