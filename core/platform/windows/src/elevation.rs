//! Windows implementation of the privileged-relaunch port: one UAC prompt.
//!
//! Elevation is delegated to PowerShell `Start-Process -Verb RunAs`, so raising
//! the prompt needs no `unsafe`. The console's relaunch is `-Wait`: it must not
//! return before the work it asked for is done. The session broker starts
//! through [`start_elevated_script`] instead, which does not wait.
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

use crate::system_shell::system_powershell;
use nrr_platform_api::elevation::{ElevatedRun, PrivilegedRelaunchPort};

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
/// is tested rather than trusted. The arguments go over as ONE pre-quoted
/// command line: Windows PowerShell joins an `-ArgumentList` array with bare
/// spaces, which splits a report path under a user name containing a space.
pub fn relaunch_script(program: &Path, args: &[String]) -> String {
    let target = start_process_target(program, args);
    format!(
        "$ErrorActionPreference='Stop'; \
         try {{ $p = Start-Process {target} \
         -Verb RunAs -WindowStyle Hidden -PassThru -Wait }} \
         catch {{ exit {ELEVATION_REFUSED} }}; \
         if ($null -eq $p) {{ exit {ELEVATION_REFUSED} }}; \
         if ($null -eq $p.ExitCode) {{ exit {EXIT_CODE_UNKNOWN} }}; \
         exit $p.ExitCode"
    )
}

/// The PowerShell that elevates `program` with `args` and returns at once, for
/// a long-lived elevated child. A declined prompt exits non-zero.
pub fn start_elevated_script(program: &Path, args: &[String]) -> String {
    let target = start_process_target(program, args);
    format!("$ErrorActionPreference='Stop'; Start-Process {target} -Verb RunAs")
}

/// `-FilePath` and `-ArgumentList` of one `Start-Process` call.
fn start_process_target(program: &Path, args: &[String]) -> String {
    let program = ps_single_quote(&program.to_string_lossy());
    // `-ArgumentList` rejects an empty value, so a no-argument call omits it.
    if args.is_empty() {
        format!("-FilePath {program}")
    } else {
        let list = ps_single_quote(&win32_command_line(args));
        format!("-FilePath {program} -ArgumentList {list}")
    }
}

/// Arguments joined into a Win32 command line, each quoted by the rules
/// `CommandLineToArgvW` and the Rust runtime parse back.
pub fn win32_command_line(args: &[String]) -> String {
    args.iter()
        .map(|a| win32_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn win32_quote(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Backslashes before a quote are escapes: double them, then
                // escape the quote itself.
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Trailing backslashes would otherwise escape the closing quote.
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Quote a string as a PowerShell single-quoted literal. The only defence
/// against a path or argument closing the literal and continuing as script;
/// PowerShell also closes a literal on the typographic single quotes, so those
/// are doubled too.
fn ps_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// Creates the file the elevated relay reports into: new, and in the directory
/// the path names rather than wherever a link swapped in by the user points.
pub fn create_relay_report(path: &Path) -> std::io::Result<std::fs::File> {
    let root = crate::pinned_file::user_temp_root()?;
    crate::pinned_file::create_new(&root, path)
}

/// Where the unelevated side must put the report path it hands to the elevated
/// one. Same directory both sides compute independently, from the shell rather
/// than from `%TEMP%`.
pub fn relay_report_dir() -> std::io::Result<std::path::PathBuf> {
    crate::pinned_file::handoff_dir()
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
        assert!(script.contains(r#"-ArgumentList '"stop"'"#), "{script}");
    }

    #[test]
    fn an_argument_cannot_close_the_literal_and_continue_as_script() {
        // The one injection surface: a quote in an argument must stay data.
        let script = relaunch_script(Path::new("nrr-cli"), &["it's; rm -rf /".to_string()]);
        assert!(script.contains(r#"'"it''s; rm -rf /"'"#), "{script}");
        let script = relaunch_script(Path::new("nrr-cli"), &["it\u{2019}s".to_string()]);
        assert!(script.contains("'\"it\u{2019}\u{2019}s\"'"), "{script}");
    }

    /// What the elevated child's runtime sees, parsed by Windows itself.
    #[allow(unsafe_code)]
    fn parsed_by_windows(command_line: &str) -> Vec<String> {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::UI::Shell::CommandLineToArgvW;

        // A program name first: its token follows different rules.
        let wide = HSTRING::from(format!("nrr-cli.exe {command_line}"));
        let mut count = 0i32;
        // SAFETY: a NUL-terminated string that outlives the call; the returned
        // array holds `count` valid strings until it is released with LocalFree.
        unsafe {
            let argv = CommandLineToArgvW(&wide, &mut count);
            assert!(!argv.is_null());
            let words = (1..count as usize)
                .map(|i| (*argv.add(i)).to_string().expect("utf-16"))
                .collect();
            let _ = LocalFree(HLOCAL(argv.cast()));
            words
        }
    }

    #[test]
    fn every_argument_reaches_the_elevated_child_whole() {
        // A report path under a user name with a space, a quote, a trailing
        // backslash and an empty value must each arrive as exactly one argument.
        let args = vec![
            "--elevated-relay".to_string(),
            r"C:\Users\Ann O'Neil\AppData\Local\Temp\NetRuleRouter\cli-elevated-1.json".to_string(),
            r#"say "hi" \"#.to_string(),
            r"C:\dir\".to_string(),
            String::new(),
        ];
        assert_eq!(parsed_by_windows(&win32_command_line(&args)), args);
        let script = relaunch_script(Path::new("nrr-cli"), &args);
        assert!(
            script.contains(&ps_single_quote(&win32_command_line(&args))),
            "{script}"
        );
    }

    #[test]
    fn the_start_script_elevates_without_waiting() {
        let script = start_elevated_script(Path::new("broker.exe"), &["a b".to_string()]);
        assert!(
            script.contains(r#"-ArgumentList '"a b"' -Verb RunAs"#),
            "{script}"
        );
        assert!(!script.contains("-Wait"), "{script}");
        let bare = start_elevated_script(Path::new("broker.exe"), &[]);
        assert!(!bare.contains("-ArgumentList"), "{bare}");
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
