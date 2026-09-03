//! Windows implementation of the privileged-relaunch port: one UAC prompt.
//!
//! Elevation is delegated to PowerShell `Start-Process -Verb RunAs`, the same
//! idiom the elevation broker uses (`apps/desktop/broker/src/spawn.rs`), so this
//! module needs no `unsafe` to raise the prompt. Unlike the broker's spawn this
//! one is `-Wait`: the caller is a console that must not return before the work
//! it asked for is done.
//!
//! ## Why the child's output cannot come back through here
//!
//! `Start-Process` has two mutually exclusive parameter sets: `-Verb` (which
//! elevates, via ShellExecute) and `-RedirectStandardOutput` (which captures).
//! Asking for both is a parameter-binding error, so an elevated child's output
//! is unreachable from this side by construction — hence
//! [`PrivilegedRelaunchPort::inherits_terminal`] answering `false` here, and the
//! caller carrying the output back itself.
//!
//! ## Telling "the user said no" from "the command failed"
//!
//! A dismissed UAC prompt makes `Start-Process` throw, which is indistinguishable
//! from any other PowerShell failure by exit code alone. So the script answers
//! with sentinels of its own ([`ELEVATION_REFUSED`], [`EXIT_CODE_UNKNOWN`]) that
//! sit far outside the console's own code table: a child that exits 1 and an
//! elevation that never happened must never look alike, because the second one
//! is worth offering to retry and the first one is not.

use std::path::Path;
use std::process::{Command, Stdio};

use nrr_platform_api::elevation::{ElevatedRun, PrivilegedRelaunchPort};
/// Absolute path of the system PowerShell.
///
/// The bare name resolves through the process search path, which on Windows
/// includes the current directory. This runs as LocalSystem (the DNS redirect)
/// or raises a UAC prompt (the relaunch), so which binary answers to the name
/// is not a detail. `%SystemRoot%` names the one Windows means.
fn system_powershell() -> std::path::PathBuf {
    match std::env::var_os("SystemRoot") {
        Some(root) => std::path::PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        None => std::path::PathBuf::from("powershell.exe"),
    }
}

/// The script's answer for "elevation did not happen": the prompt was dismissed,
/// or `Start-Process` refused before creating anything. Chosen far above the
/// console's own exit codes so a child's code can never be mistaken for it.
pub const ELEVATION_REFUSED: i32 = 199;

/// The script's answer for "it ran, but PowerShell did not report a code".
/// `-PassThru` is documented to return the process object, and with `-Wait` its
/// `ExitCode` is normally populated — normally, not always, and reporting a
/// missing code as success would turn a failed privileged operation into a
/// silent one.
pub const EXIT_CODE_UNKNOWN: i32 = 198;

/// One-shot UAC elevation of a single command.
#[derive(Debug, Default, Clone, Copy)]
pub struct UacRelaunch;

impl UacRelaunch {
    pub const fn new() -> Self {
        Self
    }
}

impl PrivilegedRelaunchPort for UacRelaunch {
    /// Never: ShellExecute starts the child in its own console, and this one
    /// launches it hidden so no window flashes at the user.
    fn inherits_terminal(&self) -> bool {
        false
    }

    fn relaunch_and_wait(&self, program: &Path, args: &[String]) -> ElevatedRun {
        let script = relaunch_script(program, args);
        let mut command = Command::new(system_powershell());
        command
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        match command.status() {
            Ok(status) => classify_exit(status.code()),
            Err(e) => ElevatedRun::Failed(format!("could not run powershell to elevate: {e}")),
        }
    }
}

/// Turn the PowerShell exit code into the port's answer.
///
/// Pure, so the sentinel contract is testable without elevating anything.
pub fn classify_exit(code: Option<i32>) -> ElevatedRun {
    match code {
        Some(ELEVATION_REFUSED) => ElevatedRun::Declined,
        Some(EXIT_CODE_UNKNOWN) => ElevatedRun::Completed { exit_code: None },
        // The child's own code, clamped into the byte a process exit code is.
        Some(other) => ElevatedRun::Completed {
            exit_code: u8::try_from(other).ok(),
        },
        None => ElevatedRun::Failed("powershell was terminated by a signal".to_string()),
    }
}

/// Build the PowerShell script that elevates `program` with `args` and waits.
///
/// Pure and public so the quoting — the one injection surface of this module —
/// is tested rather than trusted.
pub fn relaunch_script(program: &Path, args: &[String]) -> String {
    let program = ps_single_quote(&program.to_string_lossy());
    // `-ArgumentList` rejects an empty array, so a no-argument relaunch omits
    // the parameter rather than passing `@()`.
    let argument_list = if args.is_empty() {
        String::new()
    } else {
        let list = args
            .iter()
            .map(|a| ps_single_quote(a))
            .collect::<Vec<_>>()
            .join(",");
        format!(" -ArgumentList @({list})")
    };
    format!(
        "$ErrorActionPreference='Stop'; \
         try {{ $p = Start-Process -FilePath {program}{argument_list} \
         -Verb RunAs -WindowStyle Hidden -PassThru -Wait }} \
         catch {{ exit {ELEVATION_REFUSED} }}; \
         if ($null -eq $p) {{ exit {ELEVATION_REFUSED} }}; \
         if ($null -eq $p.ExitCode) {{ exit {EXIT_CODE_UNKNOWN} }}; \
         exit $p.ExitCode"
    )
}

/// Quote a string as a PowerShell single-quoted literal, doubling embedded
/// single quotes. The only defence against a path or argument closing the
/// literal and continuing as script.
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn the_script_elevates_waits_and_reports_the_childs_code() {
        let script = relaunch_script(
            &PathBuf::from(r"C:\Program Files\nrr\nrr-cli.exe"),
            &["stop".to_string()],
        );
        assert!(script.contains("-Verb RunAs"), "{script}");
        assert!(
            script.contains("-Wait"),
            "a console must not return before the work is done: {script}"
        );
        assert!(
            script.contains("-WindowStyle Hidden"),
            "no window may flash at the user: {script}"
        );
        assert!(script.contains("exit $p.ExitCode"), "{script}");
        assert!(
            script.contains(r"'C:\Program Files\nrr\nrr-cli.exe'"),
            "the path is passed as one quoted literal: {script}"
        );
        assert!(script.contains("@('stop')"), "{script}");
    }

    #[test]
    fn an_argument_cannot_close_the_literal_and_continue_as_script() {
        // The one injection surface: a quote in an argument must stay data.
        let script = relaunch_script(Path::new("nrr-cli"), &["it's; rm -rf /".to_string()]);
        assert!(script.contains("'it''s; rm -rf /'"), "{script}");
    }

    #[test]
    fn a_relaunch_without_arguments_omits_the_argument_list() {
        // `-ArgumentList @()` is a parameter-binding error, so the empty case
        // must not produce one.
        let script = relaunch_script(Path::new("nrr-cli"), &[]);
        assert!(!script.contains("-ArgumentList"), "{script}");
        assert!(script.contains("-Verb RunAs"), "{script}");
    }

    #[test]
    fn a_dismissed_prompt_is_declined_not_a_failed_command() {
        // The distinction the console reports differently — and the reason the
        // script carries a sentinel instead of leaning on PowerShell's own 1.
        assert_eq!(
            classify_exit(Some(ELEVATION_REFUSED)),
            ElevatedRun::Declined
        );
        assert_eq!(
            classify_exit(Some(1)),
            ElevatedRun::Completed { exit_code: Some(1) },
            "a child that failed is not a declined elevation"
        );
    }

    #[test]
    fn a_missing_child_code_is_reported_as_missing_not_as_success() {
        assert_eq!(
            classify_exit(Some(EXIT_CODE_UNKNOWN)),
            ElevatedRun::Completed { exit_code: None }
        );
    }

    #[test]
    fn the_childs_own_codes_survive_the_round_trip() {
        for code in [0, 3, 4, 7] {
            assert_eq!(
                classify_exit(Some(code)),
                ElevatedRun::Completed {
                    exit_code: Some(code as u8)
                }
            );
        }
    }

    #[test]
    fn a_signal_is_a_mechanism_failure() {
        assert!(matches!(classify_exit(None), ElevatedRun::Failed(_)));
    }

    #[test]
    fn this_mechanism_never_keeps_the_callers_terminal() {
        // Stated as a test because the caller's whole output-handling branch
        // hangs off this answer.
        assert!(!UacRelaunch::new().inherits_terminal());
    }
}
