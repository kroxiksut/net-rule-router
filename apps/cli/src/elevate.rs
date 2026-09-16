//! Running a privileged verb again, with administrator rights.
//!
//! The console still never elevates by itself: the default is unchanged — say
//! what is needed, exit with [`crate::exit::NEEDS_PRIVILEGE`], pop nothing. What
//! this module adds is an explicit path, taken only when the user asks for it
//! (`--elevate`) or answers a question they were shown (an interactive console).
//! A script's console is neither, so automation keeps getting exactly what it
//! gets today. That distinction is the whole design: a UAC dialog appearing
//! under a script is an interactive stop in something meant to run unattended.
//!
//! ## Re-running, not re-deciding
//!
//! The elevated process is handed argv rebuilt from the PARSED command
//! ([`canonical_argv`]), never the user's original words. What the user typed has
//! already been validated once; forwarding it verbatim would mean a second parse
//! of unvalidated input inside a privileged process, and any difference between
//! the two parses would be a privilege escalation with our name on it.
//!
//! ## Carrying the output back
//!
//! `pkexec` keeps the caller's terminal, so on Linux the elevated child prints
//! where the user is already looking and there is nothing to carry. UAC does not:
//! ShellExecute starts the child in its own window, and `Start-Process -Verb
//! RunAs` cannot redirect (the `-Verb` and `-Redirect*` parameter sets are
//! mutually exclusive). So on Windows the elevated copy re-enters this binary in
//! **relay mode**: it runs the real command as a child, captures its output, and
//! writes output and exit code to a file the unelevated parent then prints. Two
//! processes instead of one, and the reason is written down here because it looks
//! like an accident otherwise.
//!
//! The relay marker is deliberately NOT a verb in the table: it is a process
//! re-entry mode, not something a user can meaningfully invoke, and the table is
//! the console's public surface.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;

use nrr_platform_api::elevation::{ElevatedRun, PrivilegedRelaunchPort};
use nrr_shared::product_identity::PRODUCT_NAME;

use crate::exit;
use crate::parse::Command;

/// Marker that puts this process into relay mode. Not a verb — see the module
/// docs.
pub const RELAY_FLAG: &str = "--elevated-relay";

// ── What the console decided to do about privilege ───────────────────────────

/// What this invocation may do when a verb turns out to need administrator
/// rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevationPlan {
    /// Nothing: no flag, and no one to ask (a pipe, a scheduled task, CI).
    /// The console prints what is needed and exits, exactly as before.
    NotOffered,
    /// The user asked for elevation with `--elevate`, but this platform has no
    /// mechanism wired up. Saying so beats a flag that quietly does nothing.
    Unsupported,
    /// Interactive: ask, and elevate only if the answer is yes.
    Offer,
    /// `--elevate` was given: elevate without asking again.
    Requested,
}

impl ElevationPlan {
    /// Whether something else is about to happen, so the "open an elevated
    /// console and run this" hint would be wrong advice.
    pub fn acts(self) -> bool {
        matches!(self, Self::Offer | Self::Requested)
    }
}

/// Decide the plan. Pure, so the one rule that keeps scripts safe — no prompt
/// and no dialog without either a flag or a terminal — is a test rather than a
/// reading of the wiring.
pub fn plan(requested: bool, supported: bool, interactive: bool) -> ElevationPlan {
    match (requested, supported, interactive) {
        (true, false, _) => ElevationPlan::Unsupported,
        (true, true, _) => ElevationPlan::Requested,
        (false, true, true) => ElevationPlan::Offer,
        (false, _, _) => ElevationPlan::NotOffered,
    }
}

/// Whether there is a human at both ends: something to print the question on,
/// and something to read the answer from.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

// ── Rebuilding the command ───────────────────────────────────────────────────

/// The canonical spelling of a parsed command: what the elevated process is
/// asked to run.
///
/// Round-trips through the parser (there is a test), so the elevated run is the
/// same command by construction rather than by careful copying.
pub fn canonical_argv(command: &Command) -> Vec<String> {
    let word = |s: &str| s.to_string();
    match command {
        Command::Install { start_mode } => vec![
            word("install"),
            format!("--start-mode={}", start_mode.slug()),
        ],
        Command::Uninstall { purge } => {
            let mut argv = vec![word("uninstall")];
            if *purge {
                argv.push(word("--purge"));
            }
            argv
        }
        Command::Start => vec![word("start")],
        Command::Stop => vec![word("stop")],
        Command::Restart => vec![word("restart")],
        Command::Reinstall => vec![word("reinstall")],
        Command::Status => vec![word("status")],
        Command::DiagDoctor => vec![word("diag"), word("doctor")],
        Command::DiagLogs { tail } => vec![word("diag"), word("logs"), format!("--tail={tail}")],
        Command::DiagExport => vec![word("diag"), word("export")],
        Command::ResetNetwork { confirmed } => {
            let mut argv = vec![word("reset-network")];
            if *confirmed {
                argv.push(word("--confirm"));
            }
            argv
        }
        Command::Version => vec![word("version")],
        Command::Help => vec![word("help")],
    }
}

// ── Relay mode ───────────────────────────────────────────────────────────────

/// A request to run one command and report through a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRequest {
    /// Where to write the report the unelevated parent is waiting for.
    pub result_path: PathBuf,
    /// The command to run, already canonical.
    pub args: Vec<String>,
}

/// Recognise relay mode. The marker must be the FIRST argument: it is not a
/// flag of any verb, and accepting it anywhere would make it one.
pub fn relay_request(args: &[String]) -> Option<RelayRequest> {
    let (marker, rest) = args.split_first()?;
    if marker != RELAY_FLAG {
        return None;
    }
    let (path, rest) = rest.split_first()?;
    Some(RelayRequest {
        result_path: PathBuf::from(path),
        args: rest.to_vec(),
    })
}

/// Whether the relayed verb begins by stopping the service. Those are the runs
/// that wait out the post-elevation settle before starting; everything else (a
/// status read, an install of a stopped service) has nothing to tear down.
fn takes_the_service_down(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("stop" | "restart" | "uninstall")
    )
}

/// What the elevated relay reported back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayResult {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

/// Serialise a report. JSON because the payload is arbitrary console output and
/// the escaping has to be somebody else's problem.
pub fn encode_result(result: &RelayResult) -> String {
    serde_json::json!({
        "code": result.code,
        "stdout": result.stdout,
        "stderr": result.stderr,
    })
    .to_string()
}

/// Read a report back. `None` for anything unparsable — a truncated or foreign
/// file is "no report", never a made-up success.
pub fn decode_result(raw: &str) -> Option<RelayResult> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    Some(RelayResult {
        code: u8::try_from(value.get("code")?.as_u64()?).ok()?,
        stdout: value.get("stdout")?.as_str()?.to_string(),
        stderr: value.get("stderr")?.as_str()?.to_string(),
    })
}

/// Run the real command as a child, capture it, and write the report.
///
/// A child rather than an in-process call: this process cannot redirect its own
/// already-open stdout without reaching for the platform's handle table, and the
/// point of the relay is precisely that its own console is a window nobody sees.
pub fn run_relay(request: &RelayRequest) -> u8 {
    // Claimed before anything privileged runs: a path that is not ours, or one
    // that cannot be created fresh, means nobody trustworthy is waiting for it.
    if !is_report_path(&request.result_path) {
        eprintln!("elevated run: refusing a report path that is not this console's");
        return exit::FAILED;
    }
    let mut report = match crate::platform::create_relay_report(&request.result_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("elevated run: cannot create the report: {e}");
            return exit::FAILED;
        }
    };
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            write_report(
                &mut report,
                &RelayResult {
                    code: exit::FAILED,
                    stdout: String::new(),
                    stderr: format!("elevated run: cannot locate this executable: {e}\n"),
                },
            );
            return exit::FAILED;
        }
    };
    if takes_the_service_down(&request.args) {
        nrr_platform_api::elevation::settle_after_elevation();
    }
    match std::process::Command::new(exe).args(&request.args).output() {
        Ok(output) => {
            let code = output
                .status
                .code()
                .and_then(|c| u8::try_from(c).ok())
                .unwrap_or(exit::FAILED);
            write_report(
                &mut report,
                &RelayResult {
                    code,
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                },
            );
            code
        }
        Err(e) => {
            write_report(
                &mut report,
                &RelayResult {
                    code: exit::FAILED,
                    stdout: String::new(),
                    stderr: format!("elevated run: could not start the command: {e}\n"),
                },
            );
            exit::FAILED
        }
    }
}

/// Best-effort: a report that cannot be written leaves the parent saying "the
/// elevated run reported nothing", which is true and is the only honest answer.
fn write_report(file: &mut std::fs::File, result: &RelayResult) {
    let _ = file.write_all(encode_result(result).as_bytes());
}

const REPORT_PREFIX: &str = "cli-elevated-";
const REPORT_SUFFIX: &str = ".json";

/// The exchange directory both sides compute independently.
///
/// On Windows it comes from the shell, not `%TEMP%`: the elevated child
/// inherits this user's environment, so a planted variable would decide where
/// an administrator creates a file.
fn report_dir() -> PathBuf {
    #[cfg(windows)]
    {
        if let Ok(dir) = nrr_platform_windows::elevation::relay_report_dir() {
            return dir;
        }
    }
    std::env::temp_dir().join(PRODUCT_NAME)
}

/// Where the elevated copy writes its report.
///
/// The per-user temp directory: the elevated child is the SAME user (this is
/// consent, not impersonation), so it resolves to the same place. The name is
/// unpredictable so another process of this user cannot stage something at it
/// before the elevated side creates the file.
fn report_path() -> PathBuf {
    use std::hash::{BuildHasher, Hasher};

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    // Randomly keyed per process by the OS generator; no crate needed for 64 bits.
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(stamp);
    let random = hasher.finish();
    report_dir().join(format!(
        "{REPORT_PREFIX}{}-{stamp}-{random:016x}{REPORT_SUFFIX}",
        std::process::id()
    ))
}

/// Whether the elevated side may create `path`: the shape [`report_path`]
/// gives, so a redirected argument can never name anything else.
fn is_report_path(path: &std::path::Path) -> bool {
    let named = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with(REPORT_PREFIX) && n.ends_with(REPORT_SUFFIX));
    let in_our_dir = path
        .parent()
        .and_then(std::path::Path::file_name)
        .is_some_and(|dir| dir == PRODUCT_NAME);
    path.is_absolute() && named && in_our_dir
}

// ── The offer ────────────────────────────────────────────────────────────────

/// Ask whether to elevate. Anything but an explicit yes is no — this is a
/// privilege prompt, and a stray newline must not answer it.
fn ask() -> bool {
    eprint!("Retry with elevation? [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Carry out the plan for a command that came back needing privilege.
///
/// Returns the exit code of the elevated run, or `None` when nothing was run —
/// the caller then keeps the original "needs privilege" code, which is what a
/// script sees.
pub fn retry(
    plan: ElevationPlan,
    port: Option<&dyn PrivilegedRelaunchPort>,
    command: &Command,
) -> Option<u8> {
    match plan {
        ElevationPlan::NotOffered => return None,
        ElevationPlan::Unsupported => {
            eprintln!("`--elevate` is not supported on this platform yet.");
            return None;
        }
        ElevationPlan::Offer => {
            if !ask() {
                return None;
            }
        }
        ElevationPlan::Requested => {}
    }
    let port = port?;
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("cannot locate this executable to re-run it elevated: {e}");
            return Some(exit::FAILED);
        }
    };
    let argv = canonical_argv(command);

    if port.inherits_terminal() {
        // The child prints into this very terminal, so there is nothing to
        // carry and nothing to print twice.
        return Some(match port.relaunch_and_wait(&exe, &argv) {
            ElevatedRun::Completed { exit_code } => exit_code.unwrap_or(exit::FAILED),
            ElevatedRun::Declined => {
                eprintln!("Elevation was declined.");
                exit::ELEVATION_DECLINED
            }
            ElevatedRun::Failed(message) => {
                eprintln!("Could not elevate: {message}");
                exit::FAILED
            }
        });
    }

    let report = report_path();
    // Made here, unelevated, so the elevated side only ever creates a file.
    if let Some(dir) = report.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut relay_argv = Vec::with_capacity(argv.len() + 2);
    relay_argv.push(RELAY_FLAG.to_string());
    relay_argv.push(report.to_string_lossy().into_owned());
    relay_argv.extend(argv);

    let outcome = port.relaunch_and_wait(&exe, &relay_argv);
    let reported = std::fs::read_to_string(&report)
        .ok()
        .as_deref()
        .and_then(decode_result);
    let _ = std::fs::remove_file(&report);

    Some(match (outcome, reported) {
        // The report is authoritative: it is the child's own code, whereas the
        // mechanism's is whatever the shell managed to observe.
        (_, Some(result)) => {
            print!("{}", result.stdout);
            eprint!("{}", result.stderr);
            result.code
        }
        (ElevatedRun::Declined, None) => {
            eprintln!("Elevation was declined.");
            exit::ELEVATION_DECLINED
        }
        (ElevatedRun::Failed(message), None) => {
            eprintln!("Could not elevate: {message}");
            exit::FAILED
        }
        (ElevatedRun::Completed { exit_code }, None) => {
            eprintln!("The elevated run finished but reported nothing back.");
            exit_code.unwrap_or(exit::FAILED)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse;

    #[test]
    fn nothing_pops_up_without_a_flag_or_a_terminal() {
        // The rule automation depends on. A console under a pipe, a scheduled
        // task or CI must behave exactly as it did before this module existed.
        assert_eq!(plan(false, true, false), ElevationPlan::NotOffered);
        assert_eq!(plan(false, false, false), ElevationPlan::NotOffered);
        assert!(!ElevationPlan::NotOffered.acts());
    }

    #[test]
    fn a_terminal_gets_the_question_and_the_flag_skips_it() {
        assert_eq!(plan(false, true, true), ElevationPlan::Offer);
        assert_eq!(plan(true, true, true), ElevationPlan::Requested);
        // The flag works without a terminal too: that is what makes it usable
        // from a wrapper script that has already decided.
        assert_eq!(plan(true, true, false), ElevationPlan::Requested);
    }

    #[test]
    fn asking_for_elevation_where_there_is_none_says_so() {
        // A flag that silently does nothing is worse than an unsupported one.
        assert_eq!(plan(true, false, true), ElevationPlan::Unsupported);
        assert!(!ElevationPlan::Unsupported.acts());
    }

    #[test]
    fn every_command_round_trips_through_the_parser() {
        // What the elevated process runs must be the command that was parsed —
        // not a re-reading of what the user typed. Any drift here would mean a
        // privileged process running something the unprivileged one did not.
        let commands = [
            Command::Install {
                start_mode: nrr_platform_api::service_control::ServiceStartMode::WithWindows,
            },
            Command::Install {
                start_mode: nrr_platform_api::service_control::ServiceStartMode::OnAppLaunch,
            },
            Command::Uninstall { purge: false },
            Command::Uninstall { purge: true },
            Command::Start,
            Command::Stop,
            Command::Restart,
            Command::Reinstall,
            Command::Status,
            Command::DiagDoctor,
            Command::DiagLogs { tail: 17 },
            Command::DiagExport,
            Command::ResetNetwork { confirmed: false },
            Command::ResetNetwork { confirmed: true },
            Command::Version,
            Command::Help,
        ];
        for command in commands {
            let argv = canonical_argv(&command);
            let parsed = parse::parse(&argv).map(|invocation| invocation.command);
            assert_eq!(
                parsed,
                Ok(command.clone()),
                "`{argv:?}` does not parse back into {command:?}"
            );
        }
    }

    #[test]
    fn a_rebuilt_command_never_carries_the_elevation_flag_onward() {
        // The elevated copy must not be able to elevate again: one prompt per
        // invocation, and no chance of a loop.
        for command in [
            Command::Stop,
            Command::Install {
                start_mode: nrr_platform_api::service_control::ServiceStartMode::WithWindows,
            },
        ] {
            let argv = canonical_argv(&command);
            assert!(
                !argv.iter().any(|a| a.contains("elevate")),
                "rebuilt argv must not re-request elevation: {argv:?}"
            );
        }
    }

    #[test]
    fn relay_mode_is_recognised_only_as_the_first_argument() {
        let args = vec![
            RELAY_FLAG.to_string(),
            "/tmp/report.json".to_string(),
            "stop".to_string(),
        ];
        assert_eq!(
            relay_request(&args),
            Some(RelayRequest {
                result_path: PathBuf::from("/tmp/report.json"),
                args: vec!["stop".to_string()],
            })
        );
        // Anywhere else it is not relay mode — it must not become a flag of a
        // verb by being accepted in a verb's position.
        assert_eq!(
            relay_request(&["stop".to_string(), RELAY_FLAG.to_string()]),
            None
        );
        assert_eq!(relay_request(&[]), None);
        // The marker without a destination is not a relay request either; it
        // falls through to the parser, which reports an unknown verb.
        assert_eq!(relay_request(&[RELAY_FLAG.to_string()]), None);
    }

    #[test]
    fn a_report_round_trips_including_awkward_output() {
        let result = RelayResult {
            code: 3,
            stdout: "line\nwith \"quotes\" and \\ backslashes\n".to_string(),
            stderr: "stop requires an elevated console.\n".to_string(),
        };
        assert_eq!(decode_result(&encode_result(&result)), Some(result));
    }

    #[test]
    fn an_unreadable_report_is_no_report_never_a_success() {
        assert_eq!(decode_result(""), None);
        assert_eq!(decode_result("{\"code\": 0"), None, "truncated");
        assert_eq!(decode_result("{\"stdout\":\"x\"}"), None, "no code");
        assert_eq!(
            decode_result("{\"code\":300,\"stdout\":\"\",\"stderr\":\"\"}"),
            None,
            "a code no process can return"
        );
    }

    #[test]
    fn only_the_verbs_that_stop_the_service_wait_first() {
        for verb in ["stop", "restart", "uninstall"] {
            assert!(
                takes_the_service_down(&[verb.to_string()]),
                "{verb} stops the service"
            );
        }
        for verb in ["status", "start", "install", "version"] {
            assert!(
                !takes_the_service_down(&[verb.to_string()]),
                "{verb} has nothing to tear down"
            );
        }
        assert!(!takes_the_service_down(&[]));
    }

    #[test]
    fn the_report_path_is_unique_per_invocation() {
        // Two consoles elevating at once must not read each other's report.
        assert_ne!(report_path(), report_path());
    }

    #[test]
    fn the_relay_writes_only_where_this_console_would_have_asked() {
        assert!(is_report_path(&report_path()));
        let dir = report_dir();
        for foreign in [
            dir.join("cli-elevated-1.dll"),
            dir.join("other.json"),
            std::env::temp_dir().join("cli-elevated-1.json"),
            PathBuf::from("NetRuleRouter/cli-elevated-1.json"),
        ] {
            assert!(!is_report_path(&foreign), "{}", foreign.display());
        }
    }

    #[test]
    fn a_foreign_report_path_is_refused_before_anything_runs() {
        let target = std::env::temp_dir().join("nrr-cli-foreign-report.json");
        let _ = std::fs::remove_file(&target);
        let code = run_relay(&RelayRequest {
            result_path: target.clone(),
            args: vec!["version".to_string()],
        });
        assert_eq!(code, exit::FAILED);
        assert!(!target.exists(), "nothing may be written at a foreign path");
    }
}
