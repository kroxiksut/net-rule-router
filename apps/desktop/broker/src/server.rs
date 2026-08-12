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
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant, SystemTime};

use nrr_ipc_client::wire::{read_frame, write_frame};
use nrr_ipc_client::{ipc_error_to_wire, NamedPipeIpcClient};
use nrr_shared::ipc::IpcOperationName;

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
    // Single-token start-mode verbs.
    "set-start-auto",
    "set-start-demand",
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

/// Run a privileged service-control action by executing the service binary
/// subcommand. The broker is already elevated, so the child inherits the
/// elevated token with NO new UAC prompt. `CREATE_NO_WINDOW` keeps the
/// console-subsystem service binary from flashing a window / spawning a
/// visible conhost.
fn run_service_control(service_exe: &str, action: &str) -> BrokerResponse {
    if !ALLOWED_SERVICE_ACTIONS.contains(&action) {
        return BrokerResponse::err("malformed-request", format!("unknown action: {action}"));
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
    use super::rotate_broker_log;
    use std::fs;

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
