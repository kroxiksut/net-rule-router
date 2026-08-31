//! Neutral "run this command again, with administrator rights" port.
//!
//! One capability, two mechanisms that differ in more than their spelling.
//! Windows has no way to raise the privileges of a running process: elevation
//! means asking the shell to start a **new** process under an administrator
//! token, and the user answers a UAC dialog. Linux's `pkexec` also starts a new
//! process, but polkit authorises it and the helper `execve`s in place.
//!
//! ## The asymmetry a caller cannot ignore
//!
//! The elevated Windows process does **not** get the caller's console — it is a
//! different session's window, and on a hidden launch the output goes nowhere at
//! all. `pkexec` keeps stdin/stdout/stderr, so its child writes into the very
//! terminal the user is looking at.
//!
//! That difference decides whether the caller has to carry the child's output
//! back itself, so it is part of the port ([`PrivilegedRelaunchPort::inherits_terminal`])
//! rather than something each caller rediscovers. Hiding it behind a uniform
//! interface would mean either capturing output nobody needs to capture on Linux,
//! or losing it entirely on Windows.
//!
//! ## Exit codes are best-effort by construction
//!
//! ShellExecute-based elevation reports the child's exit code through a process
//! object that is not always populated, so [`ElevatedRun::Completed`] carries an
//! `Option`. A caller that must know the code reliably has to carry it out of
//! band — which the caller capturing output is doing anyway.
//!
//! ## What this port is not
//!
//! It is not an elevation *broker*. The broker (`apps/desktop/broker`) holds
//! admin rights for a whole session and proxies many operations through one
//! prompt; this port raises exactly one process and waits for it. A console runs
//! one verb and exits, so a session-long privileged channel would outlive its
//! only purpose.

use std::path::Path;
use std::sync::Mutex;

/// What an elevated re-run did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevatedRun {
    /// The elevation authority said yes and the child ran to completion.
    ///
    /// `exit_code` is the child's own code when the mechanism reports one.
    /// `None` means "it ran, but this mechanism cannot say with what code" —
    /// never "it succeeded".
    Completed { exit_code: Option<u8> },
    /// The user dismissed the prompt, or is not authorised for the action.
    /// Nothing ran.
    Declined,
    /// The elevation mechanism itself could not be used — it is missing, or the
    /// process could not be spawned. Nothing ran.
    Failed(String),
}

/// Run one command again with administrator rights, and wait for it.
pub trait PrivilegedRelaunchPort: Send + Sync {
    /// Whether the elevated child writes to the CALLER'S terminal.
    ///
    /// `true` — its output has already reached the user and must not be printed
    /// twice. `false` — the caller sees nothing and has to carry the output back
    /// itself if the user is to learn what happened.
    fn inherits_terminal(&self) -> bool;

    /// Start `program` with `args` elevated and wait for it to finish.
    ///
    /// `args` are passed as distinct argv entries, never as a shell string: an
    /// implementation that has to build one is responsible for quoting them.
    fn relaunch_and_wait(&self, program: &Path, args: &[String]) -> ElevatedRun;
}

/// Test double: records what it was asked to run and answers with a script.
///
/// Always compiled (not `#[cfg(test)]`) so the consoles' own tests can assert
/// the argv an elevated re-run would carry without elevating anything.
pub struct MockPrivilegedRelaunch {
    inherits_terminal: bool,
    outcome: ElevatedRun,
    calls: Mutex<Vec<(std::path::PathBuf, Vec<String>)>>,
}

impl MockPrivilegedRelaunch {
    /// A mock whose mechanism keeps the terminal (the `pkexec` shape).
    pub fn inheriting(outcome: ElevatedRun) -> Self {
        Self {
            inherits_terminal: true,
            outcome,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A mock whose mechanism loses the terminal (the UAC shape).
    pub fn detached(outcome: ElevatedRun) -> Self {
        Self {
            inherits_terminal: false,
            outcome,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Every `(program, args)` pair this mock was asked to run, in order.
    pub fn calls(&self) -> Vec<(std::path::PathBuf, Vec<String>)> {
        self.calls.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl PrivilegedRelaunchPort for MockPrivilegedRelaunch {
    fn inherits_terminal(&self) -> bool {
        self.inherits_terminal
    }

    fn relaunch_and_wait(&self, program: &Path, args: &[String]) -> ElevatedRun {
        self.calls
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push((program.to_path_buf(), args.to_vec()));
        self.outcome.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_mock_records_what_it_was_asked_to_run() {
        let mock = MockPrivilegedRelaunch::detached(ElevatedRun::Completed { exit_code: Some(0) });
        let program = PathBuf::from("/opt/nrr/nrr-cli");
        let args = vec!["stop".to_string()];

        assert_eq!(
            mock.relaunch_and_wait(&program, &args),
            ElevatedRun::Completed { exit_code: Some(0) }
        );
        assert_eq!(mock.calls(), vec![(program, args)]);
    }

    #[test]
    fn a_declined_run_is_not_a_completed_one() {
        // The distinction the caller reports differently: "you said no" is not
        // "the operation failed", and it must not collapse into an exit code.
        let mock = MockPrivilegedRelaunch::inheriting(ElevatedRun::Declined);
        assert_eq!(
            mock.relaunch_and_wait(Path::new("nrr-cli"), &[]),
            ElevatedRun::Declined
        );
        assert!(mock.inherits_terminal());
    }
}
