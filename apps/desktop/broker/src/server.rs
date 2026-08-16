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
use std::time::{Duration, Instant, SystemTime};

use nrr_ipc_client::wire::{read_frame, write_frame};
use nrr_ipc_client::{ipc_error_to_wire, NamedPipeIpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::product_identity::BinaryRole;

use crate::protocol::{
    BrokerRequest, BrokerResponse, BrokerServerArgs, BROKER_PING, BROKER_SERVICE_CONTROL,
    BROKER_SHUTDOWN,
};
use crate::spawn::read_and_delete_token_file;
use crate::windows_sys::{
    accept_with_parent_watch, client_process_id, create_owner_restricted_pipe,
    disconnect_and_close, open_parent_process, pipe_client_user_sid, AcceptResult, PipeIo,
};

/// Upper bound on the per-call timeout the launcher can request, so a buggy
/// or hostile caller cannot pin the broker on one service call forever.
const MAX_FORWARD_TIMEOUT: Duration = Duration::from_secs(30);

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
    // restart it. Single-token by necessity — the path is the binary's own, and
    // `check_service_binary` has already confirmed it is our sibling.
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

/// Path of the broker's own lifecycle log, `%TEMP%\NetRuleRouter\nrr-broker.log`.
fn broker_log_path() -> std::path::PathBuf {
    crate::spawn::broker_temp_dir().join("nrr-broker.log")
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
    let path = broker_log_path();
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

/// Whether `candidate` may be executed as the service binary.
///
/// The broker runs what it is told WITH AN ELEVATED TOKEN, so the path is the
/// most dangerous field on the wire: whoever can speak to the broker would
/// otherwise get arbitrary elevated execution, and the caller is a
/// non-elevated GUI — exactly the boundary elevation exists to defend.
///
/// Two conditions, both cheap: the file must be named like the service binary
/// (a rename cannot smuggle another program in), and it must live in the
/// broker's own directory (the product ships its binaries together, so a path
/// pointing anywhere else did not come from this installation). Pure over its
/// inputs so both rules are testable without an elevated process.
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
        // Without a known install directory the name check is all there is;
        // refusing outright would break the broker on a host whose own path
        // cannot be read, which is not the caller's fault.
        return Ok(());
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

/// Run a privileged service-control action by executing the service binary
/// subcommand. The broker is already elevated, so the child inherits the
/// elevated token with NO new UAC prompt. `CREATE_NO_WINDOW` keeps the
/// console-subsystem service binary from flashing a window / spawning a
/// visible conhost.
fn run_service_control(service_exe: &str, action: &str) -> BrokerResponse {
    if !ALLOWED_SERVICE_ACTIONS.contains(&action) {
        return BrokerResponse::err("malformed-request", format!("unknown action: {action}"));
    }
    if let Err(reason) = check_service_binary(Path::new(service_exe), current_exe_dir().as_deref())
    {
        broker_log(&format!("service-control: refused {service_exe}: {reason}"));
        return BrokerResponse::err("malformed-request", reason);
    }
    broker_log(&format!("service-control: {action} via {service_exe}"));
    let mut cmd = Command::new(service_exe);
    cmd.arg(action);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    match cmd.status() {
        Ok(status) if status.success() => {
            broker_log(&format!("service-control: {action} OK"));
            BrokerResponse::ok(serde_json::json!({ "action": action, "ok": true }))
        }
        Ok(status) => {
            let code = status.code().unwrap_or(-1);
            broker_log(&format!("service-control: {action} FAILED exit={code}"));
            BrokerResponse::err(
                "service-control-failed",
                format!("'{action}' exited with code {code}"),
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
    rotate_broker_log(&broker_log_path());
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

    loop {
        let pipe = match create_owner_restricted_pipe(&args.pipe_name, &args.client_sid, false) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[nrr-broker] fatal: cannot create pipe instance: {e}");
                return ExitCode::FAILURE;
            }
        };

        match accept_with_parent_watch(pipe.raw(), parent.raw()) {
            AcceptResult::Connected => {
                let outcome = serve_connection(pipe.raw(), &args, &nonce, &service, started);
                disconnect_and_close(pipe.into_raw());
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
                // Transient: drop this instance and loop. A tight failure
                // loop is throttled so a persistent error doesn't spin.
                eprintln!("[nrr-broker] accept failed: {e}");
                drop(pipe);
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
            let resp = match (action, exe) {
                (Some(a), Some(e)) => run_service_control(e, a),
                _ => BrokerResponse::err(
                    "malformed-request",
                    "service-control needs action + service-exe-path",
                ),
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
            let timeout = Duration::from_millis(request.timeout_ms.max(1)).min(MAX_FORWARD_TIMEOUT);
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
    use super::{check_service_binary, rotate_broker_log};
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
    fn an_unknown_install_directory_falls_back_to_the_name_check() {
        // Not the caller's fault, and refusing everything would brick service
        // control on such a host — but the name rule still applies.
        let candidate = Path::new("C:/anywhere").join(service_name());
        assert!(check_service_binary(&candidate, None).is_ok());
        assert!(check_service_binary(Path::new("C:/anywhere/other.exe"), None).is_err());
    }

    #[test]
    fn rotate_broker_log_moves_existing_file_to_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr-broker.log");
        fs::write(&path, b"session one\n").expect("write log");

        rotate_broker_log(&path);

        assert!(!path.exists(), "current log must be moved out of the way");
        let prev = dir.path().join("nrr-broker.prev.log");
        assert_eq!(
            fs::read_to_string(&prev).expect("read prev"),
            "session one\n"
        );
    }

    #[test]
    fn rotate_broker_log_replaces_an_older_prev() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("nrr-broker.log");
        let prev = dir.path().join("nrr-broker.prev.log");
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
        let path = dir.path().join("nrr-broker.log");

        rotate_broker_log(&path);

        assert!(!path.exists());
        assert!(!dir.path().join("nrr-broker.prev.log").exists());
    }
}
