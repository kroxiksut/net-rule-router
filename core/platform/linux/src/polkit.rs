//! The Linux [`AuthorizationPort`]: polkit, consulted through `pkcheck`.
//!
//! ## Why this and not a broker
//!
//! Windows elevates the CALLER: the launcher spawns an admin copy of itself,
//! which proxies privileged work. Linux already has the privileged process — the
//! daemon — so nothing needs to be spawned. What is missing is only the answer
//! to "may this user do this", and polkit exists to give it, including asking
//! them for a password through their session's agent.
//!
//! Introducing a `pkexec` helper instead would open a SECOND door into the
//! trusted zone, with its own environment sanitising, argv handling and audit
//! path. One door is easier to keep shut.
//!
//! ## Why the CLI rather than the D-Bus API
//!
//! `pkcheck` is polkit's supported interface for exactly this question, and its
//! exit codes are documented. Speaking D-Bus natively would mean an async runtime
//! in a crate that has none, for one question asked a few times a session. Same
//! reasoning as `nft`, `loginctl` and `resolvectl` elsewhere in this crate.
//!
//! ## The subject is a pid AND a start time
//!
//! A pid alone is reusable. Between the moment a caller connects and the moment
//! the authority answers, that process can exit and its number be reassigned —
//! and the answer would then be about somebody else. The start time from
//! `/proc/<pid>/stat` makes the pair unambiguous, which is why polkit's own
//! `--process` form takes it.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::Duration;

use nrr_platform_api::authorization::{
    AuthorizationDecision, AuthorizationPort, AuthorizationSubject,
};

/// polkit's CLI. Present wherever polkit is.
pub const PKCHECK_PROGRAM: &str = "pkcheck";

/// How long the check may take. Generous, because an interactive check waits
/// for a human to type a password; the caller decides whether to allow
/// interaction at all.
const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(120);
/// Non-interactive checks answer from policy alone and must be quick.
const SILENT_TIMEOUT: Duration = Duration::from_secs(5);

/// Consults polkit about the calling process.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolkitAuthority;

impl AuthorizationPort for PolkitAuthority {
    fn authorize(
        &self,
        subject: AuthorizationSubject,
        action: &str,
        allow_interaction: bool,
    ) -> AuthorizationDecision {
        let Some(args) = pkcheck_args(subject, action, allow_interaction) else {
            // No start time means the caller cannot be identified unambiguously,
            // and an ambiguous subject is exactly what the pair exists to
            // prevent. Refusing to ask is the safe direction.
            return AuthorizationDecision::Unavailable;
        };
        let timeout = if allow_interaction {
            INTERACTIVE_TIMEOUT
        } else {
            SILENT_TIMEOUT
        };
        match run_with_timeout(&args, timeout) {
            Some(code) => decision_for_exit_code(code),
            None => AuthorizationDecision::Unavailable,
        }
    }
}

/// Build the `pkcheck` argument list for one question.
///
/// `None` when the subject carries no start time — see the module doc. Pure, so
/// the argument shape is tested without polkit installed.
#[must_use]
pub fn pkcheck_args(
    subject: AuthorizationSubject,
    action: &str,
    allow_interaction: bool,
) -> Option<Vec<String>> {
    let start_time = subject.start_time?;
    let mut args = vec![
        "--process".to_owned(),
        format!("{},{},{}", subject.pid, start_time, subject.uid),
        "--action-id".to_owned(),
        action.to_owned(),
    ];
    if allow_interaction {
        args.push("--allow-user-interaction".to_owned());
    }
    Some(args)
}

/// Map `pkcheck`'s documented exit codes onto the neutral decision.
///
/// The codes are not interchangeable: 1 is a policy NO, 2 means nobody could ask
/// the user, and 3 means the user was asked and said no by dismissing the
/// dialog. Collapsing them would lose the only thing that tells a user what to
/// do next.
#[must_use]
pub fn decision_for_exit_code(code: i32) -> AuthorizationDecision {
    match code {
        0 => AuthorizationDecision::Allowed,
        1 => AuthorizationDecision::Denied,
        // No authentication agent, or interaction was not allowed for this call.
        2 => AuthorizationDecision::NeedsInteraction,
        // The user dismissed the prompt: a decision, and theirs.
        3 => AuthorizationDecision::Denied,
        // 126 malformed arguments, 127 internal failure, anything else unknown.
        _ => AuthorizationDecision::Unavailable,
    }
}

/// Read a process's start time — field 22 of `/proc/<pid>/stat`, in clock ticks
/// since boot.
///
/// Parsed from the LAST `)` rather than by splitting the whole line: field 2 is
/// the executable name in parentheses and may itself contain spaces and
/// brackets, which is how naive parsers of this file get the wrong number.
#[must_use]
pub fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_start_time(&stat)
}

/// The parsing half of [`process_start_time`], over the file's contents.
#[must_use]
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let after_name = stat.rfind(')')?;
    // Fields from 3 (state) on are space-separated; start time is field 22, so
    // it is the 20th of those.
    stat[after_name + 1..]
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse().ok())
}

/// Identify a connected client from its pid and uid.
#[must_use]
pub fn subject_for(pid: u32, uid: u32) -> AuthorizationSubject {
    AuthorizationSubject {
        pid,
        uid,
        start_time: process_start_time(pid),
    }
}

/// Run `pkcheck` and return its exit code, or `None` if it could not be run or
/// outlived `timeout`.
///
/// A check that hangs must not hold an IPC worker for the life of the daemon:
/// the child is killed and the answer becomes "could not ask", which the caller
/// never reads as permission.
fn run_with_timeout(args: &[String], timeout: Duration) -> Option<i32> {
    use std::process::Stdio;

    let mut child = Command::new(PKCHECK_PROGRAM)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            tracing::info!(
                target: "nrr::authorization",
                error = %e,
                "polkit is not available on this machine; privileged operations stay refused",
            );
        })
        .ok()?;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.code(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    tracing::warn!(
                        target: "nrr::authorization",
                        timeout_secs = timeout.as_secs(),
                        "the authorization check did not finish in time; treating it as unanswered",
                    );
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject() -> AuthorizationSubject {
        AuthorizationSubject {
            pid: 4321,
            uid: 1000,
            start_time: Some(987_654),
        }
    }

    /// The subject must reach polkit as the triple that makes a pid
    /// unambiguous — a bare pid would let a recycled number answer for somebody
    /// else.
    #[test]
    fn the_subject_carries_pid_start_time_and_uid() {
        let args = pkcheck_args(subject(), "com.netrulerouter.manage-service", false)
            .expect("a subject with a start time must produce arguments");

        assert_eq!(
            args,
            vec![
                "--process".to_owned(),
                "4321,987654,1000".to_owned(),
                "--action-id".to_owned(),
                "com.netrulerouter.manage-service".to_owned(),
            ],
        );
    }

    #[test]
    fn interaction_is_requested_only_when_allowed() {
        let args = pkcheck_args(subject(), "act", true).expect("arguments");

        assert!(args.contains(&"--allow-user-interaction".to_owned()));
    }

    /// Without a start time the caller cannot be identified, and asking anyway
    /// would invite the pid-reuse answer the triple exists to prevent.
    #[test]
    fn a_subject_without_a_start_time_is_not_asked_about() {
        let unidentifiable = AuthorizationSubject {
            pid: 4321,
            uid: 1000,
            start_time: None,
        };

        assert!(pkcheck_args(unidentifiable, "act", true).is_none());
        assert_eq!(
            PolkitAuthority.authorize(unidentifiable, "act", true),
            AuthorizationDecision::Unavailable,
        );
    }

    /// Each documented code means something different to the person who has to
    /// act on it: policy said no, nobody could ask, or they were asked and
    /// declined.
    #[test]
    fn every_documented_exit_code_keeps_its_meaning() {
        assert_eq!(decision_for_exit_code(0), AuthorizationDecision::Allowed);
        assert_eq!(decision_for_exit_code(1), AuthorizationDecision::Denied);
        assert_eq!(
            decision_for_exit_code(2),
            AuthorizationDecision::NeedsInteraction
        );
        assert_eq!(decision_for_exit_code(3), AuthorizationDecision::Denied);
        assert_eq!(
            decision_for_exit_code(126),
            AuthorizationDecision::Unavailable
        );
        assert_eq!(
            decision_for_exit_code(127),
            AuthorizationDecision::Unavailable
        );
    }

    /// Field 2 of `/proc/<pid>/stat` is the executable name in parentheses and
    /// may contain spaces and brackets. A parser that splits the whole line on
    /// whitespace reads the wrong field for such a process — and gets a start
    /// time that identifies nothing.
    #[test]
    fn the_start_time_survives_a_process_name_full_of_spaces() {
        // Each field holds its own number, so an off-by-one is visible in the
        // failure message rather than hidden in a plausible value.
        let fields: Vec<String> = (4..=52).map(|n| n.to_string()).collect();
        let stat = format!("1234 (my program (x86)) S {}", fields.join(" "));

        assert_eq!(parse_start_time(&stat), Some(22));
    }

    #[test]
    fn a_malformed_stat_line_yields_nothing() {
        assert_eq!(parse_start_time("nonsense with no bracket"), None);
        assert_eq!(parse_start_time("1234 (sh) S"), None);
    }

    /// Against the real file, because the field layout is the one thing a
    /// fixture cannot vouch for: this reads the test process's own start time
    /// and requires it to be a plausible tick count rather than one of the
    /// small numbers a mis-counted field would return.
    #[test]
    fn the_start_time_of_this_very_process_is_readable() {
        let pid = std::process::id();

        let start = process_start_time(pid).expect("a running process has a start time");

        // Field 21 (`itrealvalue`) is 0 on every modern kernel and field 20
        // (`num_threads`) is single digits — landing on either would be the
        // off-by-one this test exists to catch.
        assert!(
            start > 1000,
            "start time {start} looks like a neighbouring field, not clock ticks since boot",
        );
    }
}
