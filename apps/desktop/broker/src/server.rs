//! The elevated broker process (`NetRuleRouter.exe --nrr-elevated-broker`).
//!
//! Lifecycle:
//! 1. Read + delete the session nonce from the token file.
//! 2. Open one long-lived privileged `NamedPipeIpcClient` to the service.
//! 3. Open the parent launcher process handle (liveness watch).
//! 4. Accept loop — one owner-restricted pipe instance per connection,
//!    waited alongside the parent handle so the broker dies the instant the
//!    launcher exits.
//!
//! Every connection is checked three ways before its request is honoured
//! (connecting PID == parent launcher PID, token user SID == expected SID,
//! request nonce == session nonce). Control ops (`broker.ping`,
//! `broker.shutdown`) are answered locally; everything else is resolved to
//! an `IpcOperationName` and relayed to the service.

#![cfg(target_os = "windows")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use nrr_ipc_client::wire::{read_frame, write_frame};
use nrr_ipc_client::{ipc_error_to_wire, NamedPipeIpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::product_identity::BinaryRole;

use nrr_platform_windows::trusted_location::{first_reparse_point, owner_is_trusted};

use crate::log_location::{log_dir_refusal, PathFact};
use crate::protocol::{
    relay_timeout, BrokerRequest, BrokerResponse, BrokerServerArgs, BROKER_PING,
    BROKER_SERVICE_CONTROL, BROKER_SHUTDOWN, SERVICE_CONTROL_BUDGET,
};
use crate::spawn::read_and_delete_token_file;
use crate::windows_sys::{
    accept_with_parent_watch, client_process_id, create_owner_restricted_pipe,
    disconnect_and_close, open_parent_process, pipe_client_user_sid, AcceptResult, PipeIo,
};

/// How long to wait at startup for the privileged service client to reach
/// `Connected` before entering the accept loop. The dispatcher only routes
/// to the broker after the service already answered `Forbidden`, so the
/// service is up; this just lets our own client finish its handshake so the
/// first forwarded mutation finds a live connection.
const SERVICE_CONNECT_WAIT: Duration = Duration::from_secs(3);

enum Served {
    Continue,
    Shutdown,
}

/// Whitelisted service-control verbs the broker will run. Anything else is
/// rejected — the broker must never become an arbitrary elevated exec.
const ALLOWED_SERVICE_ACTIONS: &[&str] = &[
    "install",
    "uninstall",
    "start",
    "stop",
    "restart",
    // Re-point the registration at the service binary next to this broker and
    // restart it. Single-token: the path is always the broker's own sibling.
    "reinstall",
    // Single-token start-mode verbs.
    "set-start-auto",
    "set-start-demand",
    // Emergency network recovery: strips leftover packet filters, the DNS
    // redirect and our routes after a crash. Runs the service binary's own
    // teardown — the same one the console drives — so there is exactly one
    // implementation of "undo what we applied".
    "cleanup",
];

/// Verbs whose first act is to stop a running service. This process is the one
/// the UAC prompt started, so its first such run is the one that must not begin
/// while the desktop is still switching back from the prompt.
const ACTIONS_THAT_STOP_THE_SERVICE: &[&str] = &["stop", "restart", "reinstall", "uninstall"];

/// The settle belongs to the prompt, not to every command after it.
static SETTLE_SPENT: AtomicBool = AtomicBool::new(false);

/// Whether this run owes the post-elevation wait, marking it spent if so.
fn claim_post_elevation_settle(action: &str, spent: &AtomicBool) -> bool {
    ACTIONS_THAT_STOP_THE_SERVICE.contains(&action) && !spent.swap(true, Ordering::SeqCst)
}

/// Directories the broker may log into, most preferred first, each paired with
/// the first directory of our own on its path.
///
/// NOT `%TEMP%`: a fixed name in a directory the unprivileged user can write
/// lets a planted link turn every elevated append into a write elsewhere.
/// The machine's ProgramData root comes first, the install directory second.
fn log_dir_candidates() -> Vec<(PathBuf, PathBuf)> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(root) = crate::trusted_env::machine_program_data() {
        let product = root.join(nrr_shared::product_identity::PRODUCT_NAME);
        candidates.push((product.join("logs"), product));
    }
    if let Some(dir) = current_exe_dir() {
        candidates.push((dir.clone(), dir));
    }
    candidates
}

/// Path of the broker's own lifecycle log, or `None` for stderr only.
///
/// Resolved once: a directory that passed is owned by SYSTEM or Administrators,
/// so the user cannot swap it afterwards.
fn broker_log_path() -> Option<PathBuf> {
    static RESOLVED: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    RESOLVED
        .get_or_init(|| {
            for (dir, owned_from) in log_dir_candidates() {
                match prepare_trusted_log_dir(&dir, &owned_from) {
                    Ok(()) => return Some(dir.join(nrr_platform_api::paths::BROKER_LOG_FILE)),
                    // Not `broker_log`: it would re-enter this initialiser.
                    Err(reason) => eprintln!("[nrr-broker] not logging to a file there: {reason}"),
                }
            }
            None
        })
        .clone()
}

/// Creates `dir` if needed, checking before and after that no component is a
/// link and that our own directories are owned by SYSTEM or Administrators.
fn prepare_trusted_log_dir(dir: &Path, owned_from: &Path) -> Result<(), String> {
    if let Some(reason) = log_dir_refusal(dir, owned_from, true, probe_log_path) {
        return Err(reason);
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    // Again after creating: a missing directory could have been claimed by
    // the user between the check and the create.
    if let Some(reason) = log_dir_refusal(dir, owned_from, false, probe_log_path) {
        return Err(reason);
    }
    match first_reparse_point(dir) {
        Ok(None) => Ok(()),
        Ok(Some(link)) => Err(format!("{} is a link to somewhere else", link.display())),
        Err(e) => Err(e),
    }
}

fn probe_log_path(path: &Path, owner_matters: bool) -> PathFact {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return PathFact::Missing,
        Err(e) => return PathFact::Unreadable(e.to_string()),
    };
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return PathFact::Link;
    }
    if !meta.is_dir() {
        return PathFact::NotADirectory;
    }
    if !owner_matters {
        return PathFact::Directory {
            trusted_owner: true,
        };
    }
    match owner_is_trusted(path) {
        Ok(trusted_owner) => PathFact::Directory { trusted_owner },
        Err(e) => PathFact::Unreadable(e),
    }
}

/// Append one lifecycle line to the broker log file and also echo to stderr.
/// The broker is spawned with null stdio, so the file is the only durable
/// record — used to confirm the broker's lifetime (e.g. that it dies with
/// the launcher) without attaching a debugger.
fn broker_log(msg: &str) {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let line = format!("{millis} pid={} {msg}", std::process::id());
    eprintln!("[nrr-broker] {line}");
    let Some(path) = broker_log_path() else {
        return;
    };
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{line}");
    }
}

/// Rotates the broker log so a fresh broker process only accumulates lines
/// from the current elevation session: an existing file is renamed to
/// `nrr-broker.prev.log` (replacing an older one). Best-effort — a locked
/// file is left in place and the next [`broker_log`] call falls back to
/// plain append, same as before this existed. Every `run_broker_server`
/// invocation IS a new session (there is no "secondary broker" concept —
/// the dispatcher spawns at most one, tied to the parent launcher's
/// liveness), so this is safe to call unconditionally at startup.
fn rotate_broker_log(path: &std::path::Path) {
    if !path.is_file() {
        return;
    }
    let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
        return;
    };
    let prev_path = path.with_extension(format!("prev.{extension}"));
    let _ = std::fs::remove_file(&prev_path);
    let _ = std::fs::rename(path, &prev_path);
}

/// The directory this broker runs from — the product's install directory, since
/// the broker is an elevated copy of the launcher.
fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
}

/// The service binary the broker runs: always the sibling of this executable.
///
/// A path from the wire is never executed. Checking it and then running it
/// left a window in which a junction swapped under the checked directory made
/// the elevated broker run any binary of the caller's choosing. The client's
/// path survives only as a hint that must agree with ours.
fn resolve_service_binary(
    hint: Option<&Path>,
    broker_dir: Option<&Path>,
) -> Result<PathBuf, String> {
    let Some(broker_dir) = broker_dir else {
        return Err("the application's own directory is unknown".to_string());
    };
    if let Some(hint) = hint {
        check_service_binary(hint, Some(broker_dir))?;
    }
    Ok(broker_dir.join(BinaryRole::Service.host_file_name()))
}

/// Whether the client's `candidate` names the service binary beside the broker:
/// named like the service binary and living in the broker's own directory.
fn check_service_binary(candidate: &Path, broker_dir: Option<&Path>) -> Result<(), String> {
    let expected = BinaryRole::Service.host_file_name();
    let name = candidate
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Windows compares file names case-insensitively; matching that here keeps
    // the check from rejecting a legitimate `NRR-SERVICE.EXE`.
    if !name.eq_ignore_ascii_case(expected) {
        return Err(format!(
            "service binary must be named `{expected}`, got `{name}`"
        ));
    }
    let Some(broker_dir) = broker_dir else {
        // The name alone is free to forge: without the install directory there
        // is nothing tying the binary to this installation.
        return Err("the application's own directory is unknown".to_string());
    };
    let parent = candidate.parent().unwrap_or(Path::new(""));
    if !same_directory(parent, broker_dir) {
        return Err(format!(
            "service binary must sit next to the application ({}), got `{}`",
            broker_dir.display(),
            parent.display()
        ));
    }
    Ok(())
}

/// Whether two paths name the same directory.
///
/// String equality is wrong here and refused every legitimate request: the
/// caller is Qt, which spells paths with `/`, while this process derives its
/// own directory from Windows with `\`. Canonicalising both is also the
/// stricter check — it resolves `..`, short names and links before comparing,
/// so nothing can dress up a foreign directory as this one. The separator
/// fallback keeps a directory that cannot be canonicalised (removed, no rights)
/// from being silently accepted on a technicality.
fn same_directory(left: &Path, right: &Path) -> bool {
    if let (Ok(left), Ok(right)) = (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        return left == right;
    }
    normalised_dir(left) == normalised_dir(right)
}

/// Comparable spelling of a directory: one separator, no trailing one, and —
/// on Windows, where the file system is case-insensitive — one case.
fn normalised_dir(path: &Path) -> String {
    let text = path.to_string_lossy();
    let unified = if cfg!(windows) {
        text.replace('/', "\\")
    } else {
        text.into_owned()
    };
    let trimmed = unified.trim_end_matches(['\\', '/']).to_owned();
    if cfg!(windows) {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed
    }
}

/// Runs `cmd` to completion or kills it when the budget expires. Returns the
/// exit status with whatever the child wrote to stderr: the broker has no
/// console, so this is the only way the reason for a non-zero exit survives.
fn run_with_budget(
    mut cmd: Command,
    budget: Duration,
) -> std::io::Result<(std::process::ExitStatus, String)> {
    use std::io::Read;
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn()?;
    // Drained on its own thread so a chatty child cannot fill the pipe and
    // block against a parent that only polls its exit.
    let stderr = child.stderr.take();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut pipe) = stderr {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    });
    let deadline = Instant::now() + budget;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no answer within {}s", budget.as_secs()),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ok((status, reader.join().unwrap_or_default()))
}

/// The child's last non-empty stderr line, for an error message.
fn last_stderr_line(stderr: &str) -> Option<&str> {
    stderr
        .lines()
        .map(str::trim)
        .rev()
        .find(|line| !line.is_empty())
}

/// Run a privileged service-control action by executing the service binary
/// subcommand. The broker is already elevated, so the child inherits the
/// elevated token with no new UAC prompt.
fn run_service_control(hint: Option<&str>, action: &str) -> BrokerResponse {
    if !ALLOWED_SERVICE_ACTIONS.contains(&action) {
        return BrokerResponse::err("malformed-request", format!("unknown action: {action}"));
    }
    let service_exe =
        match resolve_service_binary(hint.map(Path::new), current_exe_dir().as_deref()) {
            Ok(path) => path,
            Err(reason) => {
                broker_log(&format!(
                    "service-control: refused {}: {reason}",
                    hint.unwrap_or("<no path>")
                ));
                return BrokerResponse::err("malformed-request", reason);
            }
        };
    broker_log(&format!(
        "service-control: {action} via {}",
        service_exe.display()
    ));
    if claim_post_elevation_settle(action, &SETTLE_SPENT) {
        broker_log("service-control: settling after the prompt before the first stop");
        nrr_platform_api::elevation::settle_after_elevation();
    }
    let mut cmd = Command::new(&service_exe);
    cmd.arg(action);
    // The elevated child derives its state root from `%PROGRAMDATA%`, and this
    // process inherited the environment of the user who triggered the UAC
    // prompt — who can rewrite it without any privilege. Hand the child the
    // machine's environment instead of the one we were given.
    crate::trusted_env::apply_machine_environment(&mut cmd);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match run_with_budget(cmd, SERVICE_CONTROL_BUDGET) {
        Ok((status, _)) if status.success() => {
            broker_log(&format!("service-control: {action} OK"));
            BrokerResponse::ok(serde_json::json!({ "action": action, "ok": true }))
        }
        Ok((status, stderr)) => {
            let code = status.code().unwrap_or(-1);
            let reason = last_stderr_line(&stderr)
                .map(|line| format!(": {line}"))
                .unwrap_or_default();
            broker_log(&format!(
                "service-control: {action} FAILED exit={code}{reason}"
            ));
            BrokerResponse::err(
                "service-control-failed",
                format!("'{action}' exited with code {code}{reason}"),
            )
        }
        Err(e) => {
            broker_log(&format!("service-control: {action} spawn error: {e}"));
            BrokerResponse::err("service-control-failed", format!("spawn failed: {e}"))
        }
    }
}

/// Entry point for broker mode. Never returns until the parent dies, a
/// shutdown control op arrives, or a fatal setup error occurs.
pub fn run_broker_server(args: BrokerServerArgs) -> ExitCode {
    if let Some(path) = broker_log_path() {
        rotate_broker_log(&path);
    }
    let nonce = match read_and_delete_token_file(std::path::Path::new(&args.token_file)) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("[nrr-broker] fatal: cannot read token file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let parent = match open_parent_process(args.parent_pid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("[nrr-broker] fatal: cannot open parent process: {e}");
            return ExitCode::FAILURE;
        }
    };

    // One privileged service client for the broker's whole lifetime.
    let service = NamedPipeIpcClient::start();
    wait_for_service(&service, SERVICE_CONNECT_WAIT);

    let started = Instant::now();
    broker_log(&format!(
        "ready: pipe={} parent_pid={}",
        args.pipe_name, args.parent_pid
    ));

    // ── Holding the name ─────────────────────────────────────────────────
    //
    // A named pipe exists only while at least one instance of it is open. The
    // first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a name
    // already taken is a loud failure here rather than a race; from then on the
    // name must never fall to zero instances, or another process of this user
    // could claim it in the gap, win the next accept, read the nonce out of the
    // first frame and answer `ok` to a policy write the service never saw.
    //
    // So the NEXT instance is created before the served one is released. The
    // DACL cannot help with this: the broker runs as the same user it is
    // guarding against, and a mask that let the broker add an instance would let
    // that user's other processes add one too.
    let mut pending = match create_owner_restricted_pipe(&args.pipe_name, &args.client_sid, true) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[nrr-broker] fatal: cannot create pipe instance: {e}");
            return ExitCode::FAILURE;
        }
    };
    loop {
        match accept_with_parent_watch(pending.raw(), parent.raw()) {
            AcceptResult::Connected => {
                // Claimed before the served instance is closed, so the name is
                // continuously held. A failure here is fatal: carrying on would
                // mean serving this connection and then releasing the last
                // instance of the name.
                let next =
                    match create_owner_restricted_pipe(&args.pipe_name, &args.client_sid, false) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[nrr-broker] fatal: cannot create pipe instance: {e}");
                            return ExitCode::FAILURE;
                        }
                    };
                let outcome = serve_connection(pending.raw(), &args, &nonce, &service, started);
                disconnect_and_close(pending.into_raw());
                pending = next;
                if let Served::Shutdown = outcome {
                    broker_log("shutdown requested — retiring");
                    return ExitCode::SUCCESS;
                }
            }
            AcceptResult::ParentExited => {
                broker_log("parent launcher exited — retiring");
                return ExitCode::SUCCESS;
            }
            AcceptResult::Failed(e) => {
                // Transient. The instance is replaced the same way round — new
                // one first — so the name is not released even for the moment
                // this takes. A tight failure loop is throttled so a persistent
                // error doesn't spin.
                eprintln!("[nrr-broker] accept failed: {e}");
                let next =
                    match create_owner_restricted_pipe(&args.pipe_name, &args.client_sid, false) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("[nrr-broker] fatal: cannot create pipe instance: {e}");
                            return ExitCode::FAILURE;
                        }
                    };
                drop(pending);
                pending = next;
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn wait_for_service(service: &NamedPipeIpcClient, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if service.connection_status().is_connected() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Verify the owner triple, read one request, dispatch, and write one
/// response. The pipe handle stays owned by the caller (closed after).
fn serve_connection(
    pipe: windows::Win32::Foundation::HANDLE,
    args: &BrokerServerArgs,
    nonce: &str,
    service: &NamedPipeIpcClient,
    started: Instant,
) -> Served {
    // Owner check #1 — connecting PID must be the parent launcher.
    match client_process_id(pipe) {
        Ok(pid) if pid == args.parent_pid => {}
        Ok(pid) => {
            eprintln!(
                "[nrr-broker] reject: pid {pid} != parent {}",
                args.parent_pid
            );
            return Served::Continue;
        }
        Err(e) => {
            eprintln!("[nrr-broker] reject: client pid query failed: {e}");
            return Served::Continue;
        }
    }

    // Owner check #2 — connecting token user SID must match the expected
    // owner SID (defence in depth beyond the pipe DACL).
    match pipe_client_user_sid(pipe) {
        Ok(sid) if sid.eq_ignore_ascii_case(&args.client_sid) => {}
        Ok(sid) => {
            eprintln!(
                "[nrr-broker] reject: sid {sid} != expected {}",
                args.client_sid
            );
            return Served::Continue;
        }
        Err(e) => {
            eprintln!("[nrr-broker] reject: client sid query failed: {e}");
            return Served::Continue;
        }
    }

    let mut io = match PipeIo::new(pipe) {
        Ok(io) => io,
        Err(e) => {
            eprintln!("[nrr-broker] reject: PipeIo init failed: {e}");
            return Served::Continue;
        }
    };

    let request: BrokerRequest = match read_frame(&mut io) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[nrr-broker] reject: malformed request frame: {e}");
            return Served::Continue;
        }
    };

    // Owner check #3 — the session nonce. A mismatch is the signal that a
    // same-user process tried to drive the standing elevated channel
    // without the secret only the spawning launcher holds.
    if request.nonce != nonce {
        eprintln!("[nrr-broker] reject: nonce mismatch");
        let _ = write_frame(
            &mut io,
            &BrokerResponse::err("unauthorized", "bad session token"),
        );
        return Served::Continue;
    }

    let (response, outcome) = dispatch(&request, service, started);
    if let Err(e) = write_frame(&mut io, &response) {
        eprintln!("[nrr-broker] response write failed: {e}");
    }
    outcome
}

fn dispatch(
    request: &BrokerRequest,
    service: &NamedPipeIpcClient,
    started: Instant,
) -> (BrokerResponse, Served) {
    match request.operation.as_str() {
        BROKER_PING => {
            let payload = serde_json::json!({
                "pid": std::process::id(),
                "uptime-ms": started.elapsed().as_millis() as u64,
            });
            (BrokerResponse::ok(payload), Served::Continue)
        }
        BROKER_SHUTDOWN => (
            BrokerResponse::ok(serde_json::json!({"ok": true})),
            Served::Shutdown,
        ),
        BROKER_SERVICE_CONTROL => {
            let action = request.payload.get("action").and_then(|v| v.as_str());
            let exe = request
                .payload
                .get("service-exe-path")
                .and_then(|v| v.as_str());
            let resp = match action {
                Some(a) => run_service_control(exe, a),
                None => BrokerResponse::err("malformed-request", "service-control needs action"),
            };
            (resp, Served::Continue)
        }
        slug => {
            let op = match IpcOperationName::from_slug(slug) {
                Some(op) => op,
                None => {
                    return (
                        BrokerResponse::err(
                            "unknown-operation",
                            format!("unknown operation: {slug}"),
                        ),
                        Served::Continue,
                    )
                }
            };
            let timeout = relay_timeout(request.timeout_ms);
            let response = match service.call(op, request.payload.clone(), timeout) {
                Ok(value) => BrokerResponse::ok(value),
                Err(e) => {
                    let (code, message) = ipc_error_to_wire(&e);
                    BrokerResponse::err(code, message)
                }
            };
            (response, Served::Continue)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_reason_is_the_last_non_empty_stderr_line() {
        assert_eq!(
            super::last_stderr_line(
                "warning: x
install failed: no PROGRAMDATA

"
            ),
            Some("install failed: no PROGRAMDATA")
        );
        assert_eq!(
            super::last_stderr_line(
                "  
"
            ),
            None
        );
    }

    use super::{
        check_service_binary, claim_post_elevation_settle, log_dir_candidates,
        resolve_service_binary, rotate_broker_log, AtomicBool,
    };
    use nrr_shared::product_identity::BinaryRole;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn service_name() -> &'static str {
        BinaryRole::Service.host_file_name()
    }

    #[test]
    fn the_shipped_service_binary_next_to_the_broker_is_accepted() {
        let dir = PathBuf::from("C:/Program Files/NetRuleRouter");
        let candidate = dir.join(service_name());
        assert!(check_service_binary(&candidate, Some(&dir)).is_ok());
    }

    #[test]
    fn another_program_wearing_the_right_folder_is_refused() {
        // The whole point: the broker runs this WITH AN ELEVATED TOKEN, and the
        // caller asking for it is a non-elevated GUI.
        let dir = PathBuf::from("C:/Program Files/NetRuleRouter");
        let candidate = dir.join("payload.exe");
        let err = check_service_binary(&candidate, Some(&dir)).expect_err("must refuse");
        assert!(err.contains("must be named"), "{err}");
    }

    #[test]
    fn the_right_name_from_somewhere_else_is_refused() {
        // A rename is free; the directory is what ties the binary to this
        // installation.
        let dir = PathBuf::from("C:/Program Files/NetRuleRouter");
        let candidate = Path::new("C:/Users/Public/Downloads").join(service_name());
        let err = check_service_binary(&candidate, Some(&dir)).expect_err("must refuse");
        assert!(err.contains("must sit next to"), "{err}");
    }

    /// The caller is Qt, which spells every path with `/`; this process derives
    /// its own directory from Windows, which spells it with `\`. Comparing the
    /// two as strings refused every legitimate request — service control from
    /// the GUI did nothing at all, with the reason visible only in the broker
    /// log.
    #[test]
    fn the_same_directory_spelled_with_forward_slashes_is_accepted() {
        let broker_dir = PathBuf::from(r"C:\temp\NetRuleRouter\target\debug");
        let candidate = PathBuf::from("C:/temp/NetRuleRouter/target/debug").join(service_name());
        assert!(
            check_service_binary(&candidate, Some(&broker_dir)).is_ok(),
            "a path differing only in separators names the same directory"
        );
    }

    #[test]
    fn directory_case_and_a_trailing_separator_do_not_change_the_verdict() {
        let broker_dir = PathBuf::from(r"C:\Program Files\NetRuleRouter");
        let candidate = PathBuf::from(r"c:\program files\netrulerouter\").join(service_name());
        assert!(check_service_binary(&candidate, Some(&broker_dir)).is_ok());
    }

    #[test]
    fn an_unknown_install_directory_refuses_even_the_right_name() {
        let candidate = Path::new("C:/anywhere").join(service_name());
        assert!(check_service_binary(&candidate, None).is_err());
        assert!(check_service_binary(Path::new("C:/anywhere/other.exe"), None).is_err());
    }

    #[test]
    fn the_binary_run_is_our_sibling_not_the_path_on_the_wire() {
        let dir = PathBuf::from(r"C:\Program Files\NetRuleRouter");
        let expected = dir.join(service_name());
        // A different spelling of the same file resolves to OUR spelling.
        let hint = PathBuf::from("c:/program files/netrulerouter").join(service_name());
        assert_eq!(
            resolve_service_binary(Some(&hint), Some(&dir)),
            Ok(expected.clone())
        );
        assert_eq!(resolve_service_binary(None, Some(&dir)), Ok(expected));
    }

    #[test]
    fn a_hint_that_disagrees_with_our_sibling_is_refused() {
        let dir = PathBuf::from(r"C:\Program Files\NetRuleRouter");
        let elsewhere = Path::new(r"C:\Users\Public").join(service_name());
        assert!(resolve_service_binary(Some(&elsewhere), Some(&dir)).is_err());
        let renamed = dir.join("payload.exe");
        assert!(resolve_service_binary(Some(&renamed), Some(&dir)).is_err());
    }

    #[test]
    fn without_our_own_directory_nothing_is_run() {
        assert!(resolve_service_binary(None, None).is_err());
    }

    #[test]
    fn the_settle_is_owed_once_and_only_by_a_stop() {
        let spent = AtomicBool::new(false);
        assert!(claim_post_elevation_settle("stop", &spent));
        assert!(
            !claim_post_elevation_settle("restart", &spent),
            "one prompt, one wait — later commands run straight away"
        );

        let fresh = AtomicBool::new(false);
        for action in ["start", "set-start-auto", "cleanup", "install"] {
            assert!(
                !claim_post_elevation_settle(action, &fresh),
                "{action} stops nothing"
            );
        }
        assert!(
            claim_post_elevation_settle("uninstall", &fresh),
            "the ones that stop nothing must not spend the wait"
        );
    }

    #[test]
    fn rotate_broker_log_moves_existing_file_to_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(nrr_platform_api::paths::BROKER_LOG_FILE);
        fs::write(&path, b"session one\n").expect("write log");

        rotate_broker_log(&path);

        assert!(!path.exists(), "current log must be moved out of the way");
        let prev = dir
            .path()
            .join(nrr_platform_api::paths::BROKER_PREVIOUS_LOG_FILE);
        assert_eq!(
            fs::read_to_string(&prev).expect("read prev"),
            "session one\n"
        );
    }

    #[test]
    fn rotate_broker_log_replaces_an_older_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(nrr_platform_api::paths::BROKER_LOG_FILE);
        let prev = dir
            .path()
            .join(nrr_platform_api::paths::BROKER_PREVIOUS_LOG_FILE);
        fs::write(&prev, b"stale, two sessions ago\n").expect("write stale prev");
        fs::write(&path, b"session two\n").expect("write log");

        rotate_broker_log(&path);

        assert_eq!(
            fs::read_to_string(&prev).expect("read prev"),
            "session two\n"
        );
    }

    #[test]
    fn rotate_broker_log_is_a_noop_when_no_file_exists() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(nrr_platform_api::paths::BROKER_LOG_FILE);

        rotate_broker_log(&path);

        assert!(!path.exists());
        assert!(!dir
            .path()
            .join(nrr_platform_api::paths::BROKER_PREVIOUS_LOG_FILE)
            .exists());
    }

    #[test]
    fn the_broker_log_never_lands_in_a_user_writable_temp_dir() {
        let temp = std::env::temp_dir();
        for (dir, owned_from) in log_dir_candidates() {
            assert!(
                !dir.starts_with(&temp),
                "an elevated process must not append to a fixed name under {}: {}",
                temp.display(),
                dir.display()
            );
            assert!(dir.starts_with(&owned_from));
        }
    }

    #[test]
    fn a_user_owned_log_directory_is_refused() {
        let dir = tempfile::tempdir().expect("temp dir");
        let logs = dir.path().join("logs");
        let refused = super::prepare_trusted_log_dir(&logs, dir.path());
        assert!(
            refused.is_err(),
            "a directory an ordinary account owns must not take elevated writes"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_child_that_never_answers_is_killed_at_the_budget() {
        use std::time::Instant;

        // A child that runs far longer than the budget — the shape of a
        // wedged `nrr-service.exe stop`.
        let mut cmd = std::process::Command::new("ping");
        cmd.args(["-n", "30", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());

        let started = Instant::now();
        let result = super::run_with_budget(cmd, std::time::Duration::from_millis(300));

        assert!(result.is_err(), "the broker must give up on a hung child");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the accept loop must not be held past the budget"
        );
    }
}
