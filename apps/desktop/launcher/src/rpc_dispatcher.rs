//! Launcher-side dispatcher for the Qt-host↔launcher subprocess RPC
//! channel.
//!
//! When the C++ Qt host emits `NRR_IPC_REQUEST:<json>` lines on stdout,
//! the launcher's reader loop (in `launcher.rs`) parses the line and
//! calls [`dispatch_request`]. The dispatcher resolves the operation
//! slug to `IpcOperationName`, calls the shared `IpcClient` (a real
//! `NamedPipeIpcClient` in production; a `FakeIpcClient` in tests),
//! and writes a `NRR_IPC_RESPONSE:<json>` line back to the host's
//! stdin.
//!
//! Per-request execution runs on its own short-lived `std::thread`
//! because `IpcClient::call` blocks; the launcher's main loop must
//! stay responsive to other lines (`NRR_PREFS_JSON:`, Qt warnings,
//! exit signals).
//!
//! Wire format details live in [`nrr_shared::launcher_rpc`].

use std::io::Write;
use std::process::ChildStdin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nrr_broker::BrokerHandle;
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::IpcOperationName;
use nrr_shared::launcher_rpc::{
    encode_push_line, encode_response_line, parse_request_line, LauncherRpcPush,
    LauncherRpcRequest, LauncherRpcResponse,
};

use crate::local_handlers::handle_local_request;
use crate::preset_handlers::handle_preset_request;
use crate::sidecar_handlers::{handle_sidecar_request, SidecarHandle};

/// Prefix for operation slugs handled locally by the launcher rather
/// than forwarded to the service. See `sidecar_handlers.rs` for the
/// full catalogue of supported `sidecar.*` slugs.
const SIDECAR_OPERATION_PREFIX: &str = "sidecar.";

/// The single canonical-txt parser operation routed locally. The parser
/// is a pure function over UTF-8 text (`nrr_shared::preset_parser`) and
/// has no service-side state to consult; routing it here keeps import
/// flows working when the service is down or not installed.
///
/// Matched EXACTLY, not by a `preset.` prefix: every other `preset.*`
/// slug (`preset.export.get`, `preset.import.*`, …) is a real SERVICE op
/// and must fall through to `handle_request`. A prefix guard here
/// swallowed `preset.export.get` into the local handler's UnknownOperation
/// arm → `unknown-preset-operation` (the "Save to file" export failure).
const LOCAL_PRESET_PARSE_OP: &str = "preset.parse";

/// Prefix for pure-launcher-local pure functions (no I/O, no service, no
/// sidecar). Currently hosts `local.canonical-rules-hash` for drift
/// detection; reserved for future side-effect-free helpers like
/// rules-json validation.
const LOCAL_OPERATION_PREFIX: &str = "local.";

/// The one `local.*` op that is NOT a pure function: it relays a
/// privileged service-control action through the session elevation
/// broker. Matched before the generic `local.` handler.
const SERVICE_CONTROL_OP: &str = "local.service-control";

/// The GUI's "revoke administrator approval" action. Retires the live
/// session elevation broker (the elevated process exits) so the next
/// privileged op prompts UAC again. Never spawns the broker — a no-op
/// when no session is live. Matched before the generic `local.` handler.
const BROKER_REVOKE_OP: &str = "local.broker-revoke";

/// Read-only probe of the session elevation broker: is an elevated session
/// live right now? The GUI polls this on its regular status tick to drive
/// the "revoke administrator approval" affordance, so elevation acquired
/// through ANY path (service control, the generic Forbidden relay, a rules
/// apply) becomes visible within one tick. Never spawns the broker.
const BROKER_STATUS_OP: &str = "local.broker-status";

/// Default per-request timeout. Most settings ops finish under 50 ms;
/// the storage-usage walk is the slowest at ~1 s. The catalogue's
/// per-op timeout matrix lives in `nrr-ipc-client::backend_facade_impl`
/// and is consulted on every dispatched call (the matrix wins; this
/// constant is retained for backwards compat with any downstream that
/// imports it but is no longer applied in `handle_request`).
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared handle to the Qt host's stdin. Wrapped in `Arc<Mutex<_>>` so
/// concurrent dispatcher threads can serialise their writes.
pub type SharedStdin = Arc<Mutex<ChildStdin>>;

/// Does this request line have to run on a SEPARATE service connection?
///
/// One `NamedPipeIpcClient` owns exactly one pipe connection and serialises
/// every call on it, so a request that takes tens of seconds stalls everything
/// queued behind it — including the 3 s health poll, whose timeout is what
/// paints the "Connecting to service" banner. Building a diagnostic archive
/// (zip of logs + audit, tens of MB) is exactly that kind of request: during an
/// export the GUI looked disconnected although nothing was wrong.
///
/// `ServiceHealthGet` rides the same side channel for the mirror-image reason:
/// its 1 s budget (`backend_facade_impl::timeout_for`) is measured INCLUDING
/// queue wait, so any main-channel op that legitimately takes longer than 1 s
/// (`rules.list` 5 s, `snapshot.initial.get` 3 s, `interfaces.refresh` 5 s)
/// starves the probe and paints the SAME false banner even though the pipe is
/// healthy. Moving the probe off the main channel makes it structurally
/// immune to those routine, frequent stalls. It can still queue behind a
/// concurrent `DiagnosticsExportArchive` (10 s budget) on this side channel —
/// that collision is accepted: exports are rare and user-initiated, unlike
/// the main-channel ops this fix targets, and the QML-side debounce (two
/// consecutive timeouts before the banner flips) absorbs a stray tick either
/// way.
///
/// Only side-effect-free, long-running reads belong here. Ordering between the
/// two connections is not guaranteed, so anything that MUTATES state must keep
/// using the main channel, where "issued after the previous response" also
/// means "executed after it".
pub fn request_uses_side_channel(line: &str) -> bool {
    match parse_request_line(line) {
        Some(Ok(req)) => matches!(
            IpcOperationName::from_slug(&req.operation),
            Some(IpcOperationName::DiagnosticsExportArchive)
                | Some(IpcOperationName::ServiceHealthGet)
        ),
        _ => false,
    }
}

/// Spawn a worker thread that runs the dispatcher for one parsed
/// request line. Returns the `JoinHandle` so callers can join on
/// shutdown if needed; the launcher today fires-and-forgets and
/// relies on the child's stdout EOF to signal everything has settled.
///
/// `wait_for_connect` is set for side-channel requests: the side client is
/// created lazily on the FIRST such request, and `IpcClient::call` fails
/// immediately while the background worker is still connecting — so without
/// a bounded wait the first export deterministically returned
/// `transport-disconnected` even though the service was healthy.
pub fn spawn_dispatch_worker(
    line: String,
    client: Arc<dyn IpcClient>,
    sidecar: SidecarHandle,
    broker: BrokerHandle,
    stdin: SharedStdin,
    wait_for_connect: bool,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if wait_for_connect {
            wait_until_connected(client.as_ref(), SIDE_CHANNEL_CONNECT_BUDGET);
        }
        dispatch_request(&line, &client, &sidecar, &broker, &stdin);
    })
}

/// Upper bound on how long a side-channel request waits for its freshly
/// started client to finish connect + handshake before dispatching anyway
/// (and surfacing the honest `transport-disconnected`). Generous enough for
/// a pipe open + `ContractNegotiate` round-trip; far below every side-channel
/// op timeout, so the caller's deadline still dominates.
const SIDE_CHANNEL_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// Block until `client` reports `Connected`, a state that cannot progress
/// without user action (service stopped / not installed / protocol mismatch),
/// or the budget elapses. Runs on the dispatch worker thread, so blocking
/// here never stalls the launcher's stdout loop.
fn wait_until_connected(client: &dyn IpcClient, budget: std::time::Duration) {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let status = client.connection_status();
        if status.is_connected() || status.requires_user_action() {
            return;
        }
        if std::time::Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Process a single `NRR_IPC_REQUEST:` line. The function is sync —
/// the IPC `call` blocks for up to the per-op timeout from
/// `nrr_ipc_client::ipc_operation_timeout` (1–10 s). On any failure
/// path it writes a structured error response so the C++ host's
/// correlation-id wait does not hang.
///
/// `StatusUpdatesSubscribe` is special-cased: in addition to the normal
/// request/response, the dispatcher takes a
/// `subscribe_push` receiver from the IPC client and spawns a
/// forwarder thread that streams server-pushed events to the host's
/// stdin as `NRR_IPC_PUSH:<json>` lines. The forwarder lives until the
/// receiver disconnects (client shutdown / pipe drop).
pub fn dispatch_request(
    line: &str,
    client: &Arc<dyn IpcClient>,
    sidecar: &SidecarHandle,
    broker: &BrokerHandle,
    stdin: &SharedStdin,
) {
    let parsed = match parse_request_line(line) {
        Some(Ok(req)) => req,
        Some(Err(e)) => {
            eprintln!("nrr-launcher: malformed RPC request line: {e}");
            return;
        }
        None => return,
    };

    // `sidecar.*` operations never reach the service: they read/write
    // the GUI-only per-user SQLite owned by this launcher process.
    // Routing them here means QML can prefetch
    // rule comments and passthrough sections even when the service
    // is down, and the offline pending-apply path works without a
    // service connection at all.
    if parsed.operation.starts_with(SIDECAR_OPERATION_PREFIX) {
        let response = match handle_sidecar_request(sidecar, &parsed.operation, &parsed.payload) {
            Ok(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
            Err(e) => LauncherRpcResponse::err(
                parsed.correlation_id.clone(),
                "sidecar-error",
                format!("{e}"),
            ),
        };
        write_response(stdin, &response);
        return;
    }

    // `preset.parse` parses canonical txt locally via
    // `nrr_shared::preset_parser`. The parser is a pure function; no
    // service round-trip is needed and the offline import flow keeps working
    // without a service connection. Only this exact op is local — all other
    // `preset.*` slugs fall through to the service (see `LOCAL_PRESET_PARSE_OP`).
    if parsed.operation == LOCAL_PRESET_PARSE_OP {
        let response = match handle_preset_request(&parsed.operation, &parsed.payload) {
            Ok(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
            Err(e) => {
                let code = e.wire_code();
                LauncherRpcResponse::err(parsed.correlation_id.clone(), code, format!("{e}"))
            }
        };
        write_response(stdin, &response);
        return;
    }

    // `local.service-control` unifies service start/stop/restart/install
    // through the SAME session
    // elevation broker the privileged mutations use. A non-elevated GUI
    // sends this instead of doing its own `ShellExecute runas`, so the
    // first UAC (whether an apply or a service action) spawns the broker
    // and every later privileged action — applies AND service control —
    // runs without another prompt. Payload carries `action` +
    // `service-exe-path` (resolved C++-side). On UAC decline we surface
    // `uac-declined`; on broker-unavailable, a transport error.
    if parsed.operation == SERVICE_CONTROL_OP {
        let response = match broker.call(
            nrr_broker::protocol::BROKER_SERVICE_CONTROL,
            &parsed.payload,
            Duration::from_secs(60),
        ) {
            Ok(value) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), value),
            Err(nrr_broker::BrokerCallError::Declined) => LauncherRpcResponse::err(
                parsed.correlation_id.clone(),
                "uac-declined",
                "Administrator approval is required for this service action.".to_string(),
            ),
            Err(nrr_broker::BrokerCallError::ServerError { code, message }) => {
                LauncherRpcResponse::err(parsed.correlation_id.clone(), &code, message)
            }
            Err(nrr_broker::BrokerCallError::Unavailable(e)) => {
                LauncherRpcResponse::err(parsed.correlation_id.clone(), "broker-unavailable", e)
            }
        };
        write_response(stdin, &response);
        return;
    }

    // Revoke the elevated broker session. Does NOT route through
    // `broker.call` (which would SPAWN a broker just to
    // shut it down, with a UAC prompt); `shutdown_if_active` is a no-op when
    // no session is live. Always succeeds from the GUI's point of view.
    if parsed.operation == BROKER_REVOKE_OP {
        let revoked = broker.shutdown_if_active();
        let response = LauncherRpcResponse::ok(
            parsed.correlation_id.clone(),
            serde_json::json!({ "revoked": revoked }),
        );
        write_response(stdin, &response);
        return;
    }

    // Broker-session probe. Answered locally (never spawns the broker, never
    // talks to the service) so the GUI's status tick can poll it freely even
    // while the service is down. The optional `auto-revoke-idle-secs` payload
    // field (0/absent = disabled) makes the probe double as the LAZY idle
    // auto-revoke: enforcement rides the poll the GUI already does every
    // ~1.5 s, so no timer thread exists to leak or outlive its config. The
    // idle clock restarts on every successful privileged relay.
    if parsed.operation == BROKER_STATUS_OP {
        let auto_revoked = parsed
            .payload
            .get("auto-revoke-idle-secs")
            .and_then(serde_json::Value::as_u64)
            .filter(|secs| *secs > 0)
            .is_some_and(|secs| broker.revoke_if_idle(Duration::from_secs(secs)));
        let response = LauncherRpcResponse::ok(
            parsed.correlation_id.clone(),
            serde_json::json!({
                "elevated": broker.is_session_active(),
                "auto-revoked": auto_revoked,
            }),
        );
        write_response(stdin, &response);
        return;
    }

    // `autostart.get` / `autostart.toggle` are answered locally by the
    // launcher on Windows. The service runs as
    // `LocalSystem`, so its `HKEY_CURRENT_USER` is the SYSTEM hive, not the
    // interactive user's — the tray Run key it wrote never fired at logon.
    // The launcher runs AS the user, so it owns the correct hive. Off
    // Windows `is_local_autostart_op` is always false and these fall through
    // to the service (which there runs in the user's own context).
    if crate::autostart_local::is_local_autostart_op(&parsed.operation) {
        let response = match crate::autostart_local::handle_local_autostart(
            &parsed.operation,
            &parsed.payload,
        ) {
            Ok(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
            Err(e) => {
                LauncherRpcResponse::err(parsed.correlation_id.clone(), "autostart-local-error", e)
            }
        };
        write_response(stdin, &response);
        return;
    }

    // `local.console-path.*` reads and writes the interactive user's own
    // environment, so it stays in the launcher — the only process here running
    // as that user. Matched before the generic `local.` branch, which handles
    // pure functions only: these two touch a per-user store.
    if crate::console_path_local::is_console_path_op(&parsed.operation) {
        let response = match crate::console_path_local::handle_console_path(
            &parsed.operation,
            &parsed.payload,
        ) {
            Ok(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
            Err(e) => {
                LauncherRpcResponse::err(parsed.correlation_id.clone(), "console-path-error", e)
            }
        };
        write_response(stdin, &response);
        return;
    }

    // `local.*` operations are pure functions over the payload (no
    // service hop, no sidecar). Hosts `local.canonical-rules-hash`
    // (drift detector) and `local.service-info` (compatibility banner —
    // reads the cached `ContractNegotiate` snapshot off the IPC client).
    if parsed.operation.starts_with(LOCAL_OPERATION_PREFIX) {
        let response =
            match handle_local_request(&parsed.operation, &parsed.payload, client.as_ref()) {
                Ok(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
                Err(e) => {
                    let code = e.wire_code();
                    LauncherRpcResponse::err(parsed.correlation_id.clone(), code, format!("{e}"))
                }
            };
        write_response(stdin, &response);
        return;
    }

    // For subscribe, register the push channel BEFORE making the IPC
    // call. If the call succeeds, the response carries
    // the subscription_id and we kick off the forwarder. If it fails,
    // we just drop the receiver (no harm done — push frames stop
    // arriving when the client side breaks).
    let is_subscribe = parsed.operation == IpcOperationName::StatusUpdatesSubscribe.slug();
    let push_rx = if is_subscribe {
        client.subscribe_push()
    } else {
        None
    };

    let mut response = handle_request(&parsed, client.as_ref());
    // Transparent session elevation. A `Forbidden` from a
    // privileged mutation means the GUI (hence this launcher) is not
    // elevated. Relay the SAME call through the session elevation broker:
    // the FIRST such relay spawns a long-lived elevated broker (one UAC
    // prompt); every later relay reuses it with no prompt. On success the
    // user never has to relaunch the whole app as Administrator; on UAC
    // decline we surface a localizable `uac-declined` slug; on any plumbing
    // failure we keep the original `Forbidden`. The broker uses a dedicated
    // entrypoint (`run_broker_server`) so it never re-triggers elevation.
    if response_is_forbidden(&response) {
        if let Some(op) = IpcOperationName::from_slug(&parsed.operation) {
            match broker.call(
                &parsed.operation,
                &parsed.payload,
                ipc_operation_timeout(op),
            ) {
                Ok(value) => {
                    response = LauncherRpcResponse::ok(parsed.correlation_id.clone(), value);
                }
                Err(nrr_broker::BrokerCallError::Declined) => {
                    response = LauncherRpcResponse::err(
                        parsed.correlation_id.clone(),
                        "uac-declined",
                        "Administrator approval is required to apply this change.".to_string(),
                    );
                }
                Err(nrr_broker::BrokerCallError::ServerError { code, message }) => {
                    response =
                        LauncherRpcResponse::err(parsed.correlation_id.clone(), &code, message);
                }
                Err(nrr_broker::BrokerCallError::Unavailable(_)) => {
                    // Keep the original Forbidden response.
                }
            }
        }
    }
    let response_was_ok = response.ok;
    let subscription_id = if is_subscribe && response_was_ok {
        response
            .payload
            .as_ref()
            .and_then(|p| {
                p.get("subscription-id")
                    .or_else(|| p.get("subscription_id"))
            })
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        None
    };

    write_response(stdin, &response);

    if let (Some(rx), Some(sub_id)) = (push_rx, subscription_id) {
        let stdin_clone = Arc::clone(stdin);
        let client_clone = Arc::clone(client);
        eprintln!("nrr-launcher: push forwarder started (sub={sub_id})");
        std::thread::Builder::new()
            .name("nrr-rpc-push-forwarder".into())
            .spawn(move || run_push_forwarder(rx, sub_id, client_clone, stdin_clone))
            .ok();
    }
}

/// Forwards server-pushed events from the IPC client's push receiver to
/// the C++ host's stdin as `NRR_IPC_PUSH:<json>`
/// lines. Lives for the duration of the subscription (until the
/// receiver disconnects or the host stdin closes).
///
/// This is the one hop between "the IPC client has the event" and "the QML
/// surface has the event", and it used to be silent on every path — including
/// the one where it gave up. A tray that stopped reacting was therefore
/// indistinguishable from a service that stopped pushing, which is exactly the
/// ambiguity that cost two test runs, so every frame and every exit reason is
/// reported.
fn run_push_forwarder(
    rx: std::sync::mpsc::Receiver<serde_json::Value>,
    initial_subscription_id: String,
    client: Arc<dyn IpcClient>,
    stdin: SharedStdin,
) {
    let mut forwarded: u64 = 0;
    loop {
        let payload = match rx.recv() {
            Ok(payload) => payload,
            Err(_) => {
                // The sending half is gone: the IPC client shut down, or its
                // push channel was replaced by a newer subscription.
                eprintln!(
                    "nrr-launcher: push forwarder retired — client push channel closed \
                     after {forwarded} frame(s)"
                );
                return;
            }
        };
        // Server's StatusUpdatePushFrame has `event_id` + `event`.
        let event_id = payload
            .get("event-id")
            .or_else(|| payload.get("event_id"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let event = payload
            .get("event")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let event_type = event
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        // The id the SERVER currently knows this stream by. A reconnect
        // re-subscribes and is handed a fresh one, so the id captured when the
        // forwarder started goes stale; stamping the stale value would make the
        // frames disagree with the service's own accounting.
        let subscription_id = client
            .active_subscription_id()
            .unwrap_or_else(|| initial_subscription_id.clone());
        let push = LauncherRpcPush {
            subscription_id: subscription_id.clone(),
            event_id,
            event,
        };
        let line = match encode_push_line(&push) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "nrr-launcher: push {event_type} encode failed (sub={subscription_id}): {e}"
                );
                continue;
            }
        };
        let mut guard = match stdin.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Err(e) = writeln!(*guard, "{}", line) {
            eprintln!(
                "nrr-launcher: push forwarder retired — host stdin closed while writing \
                 {event_type} (id={event_id}) after {forwarded} frame(s): {e}"
            );
            return;
        }
        let _ = guard.flush();
        forwarded += 1;
        eprintln!(
            "nrr-launcher: push {event_type} (id={event_id}) forwarded to host \
             (sub={subscription_id})"
        );
    }
}

fn handle_request(req: &LauncherRpcRequest, client: &dyn IpcClient) -> LauncherRpcResponse {
    let op = match IpcOperationName::from_slug(&req.operation) {
        Some(op) => op,
        None => {
            return LauncherRpcResponse::err(
                req.correlation_id.clone(),
                "unknown-operation",
                format!("unknown operation slug: {}", req.operation),
            );
        }
    };

    // Route through the per-op timeout matrix from
    // `nrr_ipc_client::ipc_operation_timeout` rather than a hardcoded 5 s
    // flat timeout, which would time out 10 s ops like
    // `DiagnosticsExportArchive` on slow disks. The matrix matches the
    // IPC-handler-side budget so the launcher and the service agree on
    // what "too slow" means.
    let timeout = ipc_operation_timeout(op);
    match client.call(op, req.payload.clone(), timeout) {
        Ok(value) => {
            // A finished diagnostic archive is copied from the service's
            // ProgramData dir into the user's own
            // %TEMP%\NetRuleRouter (with the GUI-side launcher logs appended)
            // and the response path rewritten to the copy. Best-effort: on
            // failure the original response passes through unchanged.
            let value = if op == IpcOperationName::DiagnosticsExportArchive {
                // Session scope for the raw-log attachments. Prefer the
                // service's echoed `logs-from-ms-effective` (the cutoff the
                // merged `logs.ndjson` was ACTUALLY trimmed to — the service
                // narrows the GUI's day floor to the current service
                // session); fall back to the request's own `logs-from-ms`
                // when talking to an older service that does not echo it.
                // Absent in both places means "full history".
                let logs_from_ms = value
                    .get("logs-from-ms-effective")
                    .and_then(serde_json::Value::as_i64)
                    .or_else(|| {
                        req.payload
                            .get("logs-from-ms")
                            .and_then(serde_json::Value::as_i64)
                    });
                // Raw-log attachment budget: the user's preference, mirrored
                // in-process by every preferences round-trip (`0` = no cap).
                crate::archive_localize::localize_export_response(
                    value,
                    logs_from_ms,
                    crate::archive_localize::service_log_budget_bytes(),
                )
            } else if op == IpcOperationName::SnapshotInitialGet {
                // The service's `autostart` field reflects the SYSTEM hive;
                // re-probe the interactive user's HKCU so the GUI's first
                // paint shows the real state. Best-effort: passes through
                // unchanged off Windows or on any probe failure.
                crate::autostart_local::patch_snapshot_autostart(value)
            } else {
                value
            };
            LauncherRpcResponse::ok(req.correlation_id.clone(), value)
        }
        Err(e) => {
            // A `Disconnected` failure means the background reconnect worker
            // is between attempts (its backoff saturates at ~5 s). Nudging it
            // here turns every failed GUI call — in particular the 3 s health
            // poll — into an immediate reconnect attempt, so the red
            // "service offline" banner clears within one poll tick of the
            // service becoming healthy instead of backoff + poll (~5–9 s).
            // Cheap when the service is genuinely down: the wake-up re-probes
            // SCM and goes back to sleep.
            if matches!(e, nrr_ipc_client::IpcClientError::Disconnected) {
                client.force_reconnect();
            }
            // Surface the typed wire code so QML can look up
            // `errors.<code>.*` locale strings. Without this every
            // server error collapsed to "ipc-call-failed" and the GUI
            // rendered raw kebab in toasts.
            let (code, message) = ipc_error_to_wire(&e);
            LauncherRpcResponse::err(req.correlation_id.clone(), code, message)
        }
    }
}

/// Map an `IpcClientError` to a kebab-case wire slug + human-readable
/// message. The slug matches the `errors.<slug>` locale key naming so the
/// GUI can do a one-shot lookup.
///
/// The canonical implementation lives in `nrr_ipc_client::ipc_error_to_wire`
/// so the launcher dispatcher and the session elevation broker
/// (`nrr-broker`) share one mapping. This thin re-export keeps the
/// existing call sites + tests in this crate working.
pub(crate) fn ipc_error_to_wire(err: &nrr_ipc_client::IpcClientError) -> (&'static str, String) {
    nrr_ipc_client::ipc_error_to_wire(err)
}

/// True when a response is a `forbidden` server error (the only signal
/// the launcher uses to trigger session elevation).
fn response_is_forbidden(resp: &LauncherRpcResponse) -> bool {
    !resp.ok
        && resp
            .error
            .as_ref()
            .map(|e| e.code == "forbidden")
            .unwrap_or(false)
}

fn write_response(stdin: &SharedStdin, resp: &LauncherRpcResponse) {
    let line = match encode_response_line(resp) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "nrr-launcher: response serialisation failed (corr={}): {e}",
                resp.correlation_id,
            );
            return;
        }
    };
    let mut guard = match stdin.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Err(e) = writeln!(*guard, "{}", line) {
        eprintln!(
            "nrr-launcher: failed to write RPC response (corr={}): {e}",
            resp.correlation_id,
        );
        return;
    }
    if let Err(e) = guard.flush() {
        eprintln!(
            "nrr-launcher: failed to flush RPC response (corr={}): {e}",
            resp.correlation_id,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_ipc_client::{ConnectionStatus, IpcClientError};
    use std::sync::Mutex as StdMutex;

    /// Pre-scripted outcome variants for the `ScriptedClient`. Avoids
    /// requiring `Clone` on `IpcClientError` (which the trait does not
    /// implement). The `ServerError` variant carries the inner
    /// constituent parts so tests can drive each `IpcErrorCode` path
    /// through the dispatcher.
    enum ScriptedOutcome {
        Ok(serde_json::Value),
        Disconnected,
        ServerError(IpcClientError),
    }

    /// In-process fake `IpcClient` for unit tests. Records the
    /// last-seen request and lets the test pre-script the response.
    /// Outcome is consumed on the first `call` (take semantics) so we
    /// don't need `Clone` on `IpcClientError`.
    struct ScriptedClient {
        outcome: StdMutex<Option<ScriptedOutcome>>,
        last_call: StdMutex<Option<(IpcOperationName, serde_json::Value)>>,
    }

    impl ScriptedClient {
        fn new(outcome: ScriptedOutcome) -> Self {
            Self {
                outcome: StdMutex::new(Some(outcome)),
                last_call: StdMutex::new(None),
            }
        }
    }

    impl IpcClient for ScriptedClient {
        fn call(
            &self,
            op: IpcOperationName,
            payload: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, IpcClientError> {
            *self.last_call.lock().unwrap() = Some((op, payload));
            let outcome = self
                .outcome
                .lock()
                .unwrap()
                .take()
                .expect("ScriptedClient called more than once");
            match outcome {
                ScriptedOutcome::Ok(v) => Ok(v),
                ScriptedOutcome::Disconnected => Err(IpcClientError::Disconnected),
                ScriptedOutcome::ServerError(err) => Err(err),
            }
        }
        fn connection_status(&self) -> ConnectionStatus {
            ConnectionStatus::Connected
        }
        fn force_reconnect(&self) {}
    }

    fn parse_response_from_buffer(buffer: &[u8]) -> LauncherRpcResponse {
        let line = std::str::from_utf8(buffer)
            .expect("utf-8")
            .trim_end_matches('\n');
        nrr_shared::launcher_rpc::parse_response_line(line)
            .expect("response line")
            .expect("valid json")
    }

    // Cross-platform stdin sink — `ChildStdin` is platform-coupled, so the
    // tests use a mock writer that captures bytes. Switch the production
    // helper to use `Vec<u8>` when running tests via a trait object.
    //
    // Kept simple on purpose: the public `dispatch_request` requires a real
    // `ChildStdin`. The tests below cover the request → response mapping at
    // the `handle_request` level instead, which is the bit that needs no IO.

    /// Client that reports `Connecting` for its first few status reads and
    /// `Connected` afterwards, mimicking a freshly started side channel whose
    /// background worker is still doing connect + handshake.
    struct SlowConnectClient {
        reads: StdMutex<u32>,
        connect_after: u32,
    }

    impl SlowConnectClient {
        fn new(connect_after: u32) -> Self {
            Self {
                reads: StdMutex::new(0),
                connect_after,
            }
        }

        fn reads(&self) -> u32 {
            *self.reads.lock().unwrap()
        }
    }

    impl IpcClient for SlowConnectClient {
        fn call(
            &self,
            _op: IpcOperationName,
            _payload: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, IpcClientError> {
            Err(IpcClientError::Disconnected)
        }
        fn connection_status(&self) -> ConnectionStatus {
            let mut reads = self.reads.lock().unwrap();
            *reads += 1;
            if *reads > self.connect_after {
                ConnectionStatus::Connected
            } else {
                ConnectionStatus::Connecting
            }
        }
        fn force_reconnect(&self) {}
    }

    /// Client stuck in a state only the user can resolve.
    struct ServiceStoppedClient;

    impl IpcClient for ServiceStoppedClient {
        fn call(
            &self,
            _op: IpcOperationName,
            _payload: serde_json::Value,
            _timeout: Duration,
        ) -> Result<serde_json::Value, IpcClientError> {
            Err(IpcClientError::Disconnected)
        }
        fn connection_status(&self) -> ConnectionStatus {
            ConnectionStatus::ServiceStopped
        }
        fn force_reconnect(&self) {}
    }

    #[test]
    fn wait_until_connected_returns_once_the_client_connects() {
        // The first export used to fail deterministically: the side channel is
        // created on that very request and `call` rejects immediately while the
        // worker is still connecting.
        let client = SlowConnectClient::new(2);
        wait_until_connected(&client, Duration::from_secs(5));
        assert!(
            client.reads() >= 3,
            "must keep polling until the status flips, saw {} reads",
            client.reads()
        );
        assert!(client.connection_status().is_connected());
    }

    #[test]
    fn wait_until_connected_gives_up_on_a_stopped_service() {
        // Waiting out the whole budget for a state that cannot change without
        // the user starting the service would just delay an honest error.
        let started = std::time::Instant::now();
        wait_until_connected(&ServiceStoppedClient, Duration::from_secs(5));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "a user-action state must not burn the connect budget"
        );
    }

    #[test]
    fn handle_request_unknown_operation_returns_error() {
        let client = ScriptedClient::new(ScriptedOutcome::Ok(serde_json::json!({})));
        let req = LauncherRpcRequest {
            correlation_id: "c-1".into(),
            operation: "totally.made-up.op".into(),
            payload: serde_json::json!({}),
        };
        let resp = handle_request(&req, &client);
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        assert_eq!(err.code, "unknown-operation");
    }

    #[test]
    fn handle_request_known_operation_forwards_to_client() {
        let payload = serde_json::json!({"foo": 1});
        let client = ScriptedClient::new(ScriptedOutcome::Ok(payload.clone()));
        let req = LauncherRpcRequest {
            correlation_id: "c-2".into(),
            operation: IpcOperationName::ServiceHealthGet.slug().to_string(),
            payload: serde_json::json!({}),
        };
        let resp = handle_request(&req, &client);
        assert!(resp.ok);
        assert_eq!(resp.payload.unwrap(), payload);
        let recorded = client.last_call.lock().unwrap().clone().unwrap();
        assert_eq!(recorded.0, IpcOperationName::ServiceHealthGet);
    }

    #[test]
    fn handle_request_routes_block_16_13_opcodes() {
        // Sanity check — every opcode added to the catalog resolves
        // through `from_slug` so the dispatcher forwards (does NOT
        // emit `unknown-operation`). The actual
        // payload routing is exercised by the handler-side
        // integration tests; here we only verify slug-recognition
        // at the launcher boundary.
        for op in [
            IpcOperationName::ExplainGet,
            IpcOperationName::DiagnosticsExportArchive,
            IpcOperationName::ServiceStabilityConfigGet,
            IpcOperationName::ServiceStabilityConfigSet,
        ] {
            let payload = serde_json::json!({});
            let client = ScriptedClient::new(ScriptedOutcome::Ok(payload.clone()));
            let req = LauncherRpcRequest {
                correlation_id: format!("c-1613-{}", op.slug()),
                operation: op.slug().to_string(),
                payload,
            };
            let resp = handle_request(&req, &client);
            assert!(
                resp.ok,
                "op {} must route through dispatcher (got error {:?})",
                op.slug(),
                resp.error
            );
            let recorded = client.last_call.lock().unwrap().clone().unwrap();
            assert_eq!(recorded.0, op, "dispatcher must pass parsed op {op:?}");
        }
    }

    #[test]
    fn handle_request_propagates_transport_disconnected_with_typed_slug() {
        // The dispatcher maps each IpcClientError variant to a stable
        // kebab-case slug so the GUI can do `errors.<slug>` lookups.
        let client = ScriptedClient::new(ScriptedOutcome::Disconnected);
        let req = LauncherRpcRequest {
            correlation_id: "c-3".into(),
            operation: IpcOperationName::SnapshotInitialGet.slug().to_string(),
            payload: serde_json::json!({}),
        };
        let resp = handle_request(&req, &client);
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        assert_eq!(err.code, "transport-disconnected");
        assert!(err.message.contains("not connected"));
    }

    #[test]
    fn handle_request_maps_precondition_failed_expired_to_confirmation_expired() {
        // The wire schema doesn't yet have a dedicated
        // `ConfirmationExpired` code; the dispatcher detects the
        // expiration substring in the server message and promotes
        // it so QML doesn't need to grep English text.
        use nrr_ipc_client::IpcClientError;
        let client =
            ScriptedClient::new(ScriptedOutcome::ServerError(IpcClientError::ServerError {
                op: IpcOperationName::MutationSubmit,
                code: nrr_shared::ipc_transport::IpcErrorCode::PreconditionFailed,
                message: "confirmation token expired — re-run dry-run".into(),
            }));
        let req = LauncherRpcRequest {
            correlation_id: "c-4".into(),
            operation: IpcOperationName::MutationSubmit.slug().to_string(),
            payload: serde_json::json!({}),
        };
        let resp = handle_request(&req, &client);
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        assert_eq!(err.code, "confirmation-expired");
    }

    #[test]
    fn handle_request_maps_forbidden_server_error() {
        use nrr_ipc_client::IpcClientError;
        let client =
            ScriptedClient::new(ScriptedOutcome::ServerError(IpcClientError::ServerError {
                op: IpcOperationName::RoutePolicyUpdate,
                code: nrr_shared::ipc_transport::IpcErrorCode::Forbidden,
                message: "non-admin GUI cannot mutate".into(),
            }));
        let req = LauncherRpcRequest {
            correlation_id: "c-5".into(),
            operation: IpcOperationName::RoutePolicyUpdate.slug().to_string(),
            payload: serde_json::json!({}),
        };
        let resp = handle_request(&req, &client);
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        assert_eq!(err.code, "forbidden");
        assert_eq!(err.message, "non-admin GUI cannot mutate");
    }

    #[test]
    fn request_uses_side_channel_covers_health_and_export_only() {
        use nrr_shared::launcher_rpc::encode_request_line;

        let side_ops = [
            IpcOperationName::DiagnosticsExportArchive,
            IpcOperationName::ServiceHealthGet,
        ];
        for op in side_ops {
            let req = LauncherRpcRequest {
                correlation_id: format!("c-{}", op.slug()),
                operation: op.slug().to_string(),
                payload: serde_json::json!({}),
            };
            let line = encode_request_line(&req).unwrap();
            assert!(
                request_uses_side_channel(&line),
                "{} must use the side channel",
                op.slug()
            );
        }

        // A representative main-channel op — must NOT be routed to the side
        // channel (mutations and the frequent snapshot/rules reads keep
        // strict ordering on the primary connection).
        let main_req = LauncherRpcRequest {
            correlation_id: "c-main".into(),
            operation: IpcOperationName::RulesList.slug().to_string(),
            payload: serde_json::json!({}),
        };
        let main_line = encode_request_line(&main_req).unwrap();
        assert!(!request_uses_side_channel(&main_line));
    }

    #[test]
    fn parse_response_from_buffer_round_trips() {
        let resp = LauncherRpcResponse::ok("c-x", serde_json::json!({"y": 2}));
        let line = encode_response_line(&resp).unwrap();
        let buffer = format!("{line}\n");
        let parsed = parse_response_from_buffer(buffer.as_bytes());
        assert_eq!(parsed.correlation_id, "c-x");
        assert!(parsed.ok);
    }
}
