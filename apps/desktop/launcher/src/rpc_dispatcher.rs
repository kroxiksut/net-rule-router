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
use std::time::{Duration, Instant};

use nrr_broker::protocol::client_answer_timeout;
use nrr_broker::BrokerHandle;
use nrr_ipc_client::{ipc_operation_timeout, IpcClient};
use nrr_shared::ipc::{IpcClientProfile, IpcOperationName};
use nrr_shared::launcher_rpc::{
    encode_push_line, encode_response_line, parse_request_line, HostAnswerDeadlines,
    LauncherRpcPush, LauncherRpcRequest, LauncherRpcResponse,
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
/// The elevated broker is alive but still on an earlier (or this) operation.
/// Not `Forbidden`: nothing was refused, and a retry must not look needed.
const BROKER_BUSY_CODE: &str = "elevated-operation-running";

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

/// Shared handle to the Qt host's stdin. Wrapped in `Arc<Mutex<_>>` so
/// concurrent dispatcher threads can serialise their writes.
pub type SharedStdin = Arc<Mutex<ChildStdin>>;

/// Which service connection a request line travels on.
///
/// One `NamedPipeIpcClient` owns one pipe connection and serves one call at a
/// time, so a slow request stalls everything queued behind it — including the
/// health probe, whose 1 s budget counts queue wait and whose second timeout in
/// a row paints "Connecting to service" while the service is fine.
///
/// - `Main`: mutations and the push subscription. Ordering between connections
///   is not guaranteed, so anything that MUTATES state stays here, where
///   "issued after the previous response" also means "executed after it".
/// - `Side`: side-effect-free reads and diagnostic queries, the health probe
///   among them, so a mutation with a 30 s budget cannot starve them.
/// - `Export`: the diagnostic archive alone. A build with raw logs runs for
///   seconds; on `Side` it starved the health probe into the same false banner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcLane {
    Main,
    Side,
    Export,
}

pub fn request_lane(line: &str) -> RpcLane {
    let Some(Ok(req)) = parse_request_line(line) else {
        return RpcLane::Main;
    };
    match IpcOperationName::from_slug(&req.operation) {
        // The forwarder streams pushes from the client the subscription was
        // made on, whatever its class says.
        Some(IpcOperationName::StatusUpdatesSubscribe | IpcOperationName::StatusUpdatesPoll) => {
            RpcLane::Main
        }
        // Audited as a DiagnosticAction (the archive is a file write), but for
        // transport it is a long read.
        Some(IpcOperationName::DiagnosticsExportArchive) => RpcLane::Export,
        Some(op) if side_channel_class(op, &req.payload) => RpcLane::Side,
        _ => RpcLane::Main,
    }
}

/// The classes the service already lets bypass its mutation queue.
fn side_channel_class(op: IpcOperationName, payload: &serde_json::Value) -> bool {
    matches!(
        nrr_shared::ipc_transport::canonical_operation_class(op, payload),
        nrr_shared::ipc_transport::IpcOperationClass::ReadSnapshot
            | nrr_shared::ipc_transport::IpcOperationClass::DiagnosticQuery
    )
}

/// One service connection per [`RpcLane`], each opened on first use.
#[derive(Default)]
pub struct LaneClients {
    main: Option<LaneClient>,
    side: Option<LaneClient>,
    export: Option<LaneClient>,
}

struct LaneClient {
    client: Arc<dyn IpcClient>,
    started: Instant,
}

impl LaneClients {
    /// The lane's client, and how long a request may wait for it to connect.
    ///
    /// Every client is created by the request that first needs it, and `call`
    /// fails at once while it is still connecting: the first export, and the
    /// tray's startup subscribe, returned `transport-disconnected` from a
    /// healthy service. Side and export requests always wait. The main lane
    /// waits only while its client is young — later, a disconnect is a real one
    /// and its callers must hear so at once, not after the budget.
    pub fn client_for(
        &mut self,
        lane: RpcLane,
        now: Instant,
        start: impl FnOnce() -> Arc<dyn IpcClient>,
    ) -> (Arc<dyn IpcClient>, Duration) {
        let slot = match lane {
            RpcLane::Main => &mut self.main,
            RpcLane::Side => &mut self.side,
            RpcLane::Export => &mut self.export,
        };
        let entry = slot.get_or_insert_with(|| LaneClient {
            client: start(),
            started: now,
        });
        let budget = match lane {
            RpcLane::Main => {
                CONNECT_BUDGET.saturating_sub(now.saturating_duration_since(entry.started))
            }
            RpcLane::Side | RpcLane::Export => CONNECT_BUDGET,
        };
        (Arc::clone(&entry.client), budget)
    }
}

/// Spawn a worker thread that runs the dispatcher for one parsed
/// request line. Returns the `JoinHandle` so callers can join on
/// shutdown if needed; the launcher today fires-and-forgets and
/// relies on the child's stdout EOF to signal everything has settled.
///
/// `connect_budget` comes from [`LaneClients::client_for`]; zero dispatches at once.
/// `profile` is the surface the service knows this launcher as.
pub fn spawn_dispatch_worker(
    line: String,
    client: Arc<dyn IpcClient>,
    sidecar: SidecarHandle,
    broker: BrokerHandle,
    stdin: SharedStdin,
    connect_budget: Duration,
    profile: IpcClientProfile,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if !connect_budget.is_zero() {
            wait_until_connected(client.as_ref(), connect_budget);
        }
        dispatch_request(&line, &client, &sidecar, &broker, &stdin, profile);
    })
}

/// Upper bound on how long a request waits for a freshly started client to
/// finish connect + handshake before dispatching anyway (and surfacing the
/// honest `transport-disconnected`). Generous enough for a pipe open +
/// `ContractNegotiate` round-trip; far below every op's timeout, so the
/// caller's deadline still dominates.
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

/// The host's wait on top of the dispatcher's own bound: scheduling, the two
/// pipe hops and a GUI thread that is busy for a moment.
const HOST_ANSWER_MARGIN: Duration = Duration::from_secs(5);

/// The host's wait for the launcher's own `local.*` / `sidecar.*` operations,
/// which have no service budget to derive from.
const LOCAL_ANSWER_DEADLINE: Duration = Duration::from_secs(30);

/// Longest the dispatcher may take to answer a service operation: a young
/// lane's connect wait, the call (queue wait included) and one relay through a
/// live elevated broker after a `Forbidden`. A UAC prompt is the user's time
/// and is not counted; an answer that outlives it reaches the host late.
fn dispatcher_answer_bound(op: IpcOperationName) -> Duration {
    let call = ipc_operation_timeout(op);
    CONNECT_BUDGET
        + call
        + client_answer_timeout(nrr_broker::protocol::BROKER_PING, Duration::ZERO)
        + client_answer_timeout(op.slug(), call)
}

/// The deadlines the Qt host holds each request to, handed over in the QML
/// context. Derived here so the host never gives up on an answer the
/// dispatcher is still allowed to produce.
pub fn host_answer_deadlines() -> HostAnswerDeadlines {
    let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    HostAnswerDeadlines {
        default_ms: ms(LOCAL_ANSWER_DEADLINE),
        operations_ms: IpcOperationName::ALL
            .into_iter()
            .map(|op| {
                (
                    op.slug().to_string(),
                    ms(dispatcher_answer_bound(op) + HOST_ANSWER_MARGIN),
                )
            })
            .collect(),
    }
}

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
    profile: IpcClientProfile,
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
            Err(nrr_broker::BrokerCallError::StillRunning(e)) => {
                LauncherRpcResponse::err(parsed.correlation_id.clone(), BROKER_BUSY_CODE, e)
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

    // `autostart.toggle` is answered locally by the launcher: autostart is a
    // per-user setting, and no background service runs as that user. On
    // Windows the service is `LocalSystem`, so its `HKEY_CURRENT_USER` is the
    // SYSTEM hive; on Linux the daemon is root, so its `$HOME` is `/root`.
    // Either would write an entry the session never reads. Where no
    // user-context mechanism exists yet (macOS), `is_local_autostart_op` is
    // false and it falls through to the service.
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

    // The user's own "Check for updates": a network request, so matched before
    // the pure `local.*` functions.
    if parsed.operation == crate::update_check_fetch::MANUAL_CHECK_OP {
        let response = match crate::update_check_fetch::run_manual_check() {
            Some(payload) => LauncherRpcResponse::ok(parsed.correlation_id.clone(), payload),
            None => LauncherRpcResponse::err(
                parsed.correlation_id.clone(),
                crate::update_check_fetch::CHECK_FAILED_CODE,
                "The release page did not answer.".to_string(),
            ),
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
    // Transparent session elevation: a `Forbidden` that elevation can cure is
    // relayed through the session broker (one UAC, reused all session). On UAC
    // decline we surface `uac-declined`; on any plumbing failure we keep the
    // original `Forbidden`.
    if let Some(op) = IpcOperationName::from_slug(&parsed.operation) {
        if broker_may_retry(op, &parsed.payload, profile, &response) {
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
                Err(nrr_broker::BrokerCallError::StillRunning(message)) => {
                    response = LauncherRpcResponse::err(
                        parsed.correlation_id.clone(),
                        BROKER_BUSY_CODE,
                        message,
                    );
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

    // The prepared channel takes over only now, when the subscribe is known to
    // have gone through. A failed one leaves the channel that was already
    // delivering exactly where it was.
    if is_subscribe {
        if subscription_id.is_some() {
            client.commit_push();
        } else {
            client.abandon_push();
        }
    }

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
                // Which forwarder died matters, and until now the line did
                // not say: it fires once per re-subscribe, so a reader sees
                // a stream of identical retirements with no way to tell the
                // one that was carrying events from the one a retry had
                // replaced a moment earlier.
                eprintln!(
                    "nrr-launcher: push forwarder retired (sub={initial_subscription_id}) — \
                     client push channel closed after {forwarded} frame(s)"
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

/// Drop the cached snapshots a just-executed mutation invalidates.
///
/// Best-effort and deliberately quiet: a cache that cannot be cleared is a
/// stale read later, never a failed mutation now.
/// Attach the user's archive log-budget preference to an export request.
///
/// `0` is the preference's "no cap I chose" and is left off the wire, where it
/// would read as "keep nothing". A payload that is not an object passes through
/// untouched — the service rejects it on its own terms.
fn with_raw_log_budget(payload: serde_json::Value) -> serde_json::Value {
    let budget = crate::archive_localize::service_log_budget_bytes();
    if budget == 0 {
        return payload;
    }
    let serde_json::Value::Object(mut map) = payload else {
        return payload;
    };
    map.insert(
        "raw-log-budget-bytes".to_string(),
        serde_json::Value::from(budget),
    );
    serde_json::Value::Object(map)
}

fn invalidate_cache_after_mutation(op: IpcOperationName, payload: &serde_json::Value) {
    let Some(kind) = mutation_kind_to_invalidate(op, payload) else {
        return;
    };
    if let Ok(cache) = nrr_ipc_client::snapshot_cache::FileCache::at_default_location() {
        let _ = cache.invalidate_for_mutation(kind);
    }
}

/// Which mutation just took effect, if any. Split out so the decision is
/// testable without touching the user's real cache directory.
fn mutation_kind_to_invalidate(
    op: IpcOperationName,
    payload: &serde_json::Value,
) -> Option<nrr_shared::ipc_payloads::MutationKind> {
    if op != IpcOperationName::MutationSubmit {
        return None;
    }
    // A dry run changes nothing; only the confirm pass does.
    if payload
        .get("dry-run")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    payload
        .get("mutation-kind")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
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
    // The raw service-log section is built by the SERVICE now (it reads its own
    // files and returns only what this caller may see), so the user's byte cap
    // has to travel with the request instead of being applied here after the
    // fact. Only for the export, and only when the preference is actually set.
    let payload = if op == IpcOperationName::DiagnosticsExportArchive {
        with_raw_log_budget(req.payload.clone())
    } else {
        req.payload.clone()
    };
    match client.call(op, payload, timeout) {
        Ok(value) => {
            // Mutations travel this path, not the facade's, so the facade's
            // cache invalidation never ran: the snapshot files kept answering
            // with pre-edit policy for as long as their TTL allowed. Drop the
            // entries a successful mutation makes wrong, right here.
            invalidate_cache_after_mutation(op, &req.payload);
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
                crate::archive_localize::localize_export_response(value, logs_from_ms)
            } else if op == IpcOperationName::SnapshotInitialGet {
                // The service's `autostart` field reflects its own system
                // context; re-probe the interactive user's so the GUI's first
                // paint shows the real state. Best-effort: passes through
                // unchanged on any probe failure.
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

/// True when a response is a `forbidden` server error.
fn response_is_forbidden(resp: &LauncherRpcResponse) -> bool {
    !resp.ok
        && resp
            .error
            .as_ref()
            .map(|e| e.code == "forbidden")
            .unwrap_or(false)
}

/// Whether a service answer to `op` may be retried through the elevated broker.
///
/// The service answers `Forbidden` both for "needs an administrator" and for
/// "this surface may not call that at all". Only the first is curable by
/// elevation; relaying the second raised a UAC prompt from a tray read. The
/// surface refusal is recognised by running the service's own profile gates
/// here: when this profile passes them, the refusal came from a later check.
fn broker_may_retry(
    op: IpcOperationName,
    payload: &serde_json::Value,
    profile: IpcClientProfile,
    response: &LauncherRpcResponse,
) -> bool {
    if !response_is_forbidden(response) {
        return false;
    }
    let class = nrr_shared::ipc_transport::canonical_operation_class(op, payload);
    profile.permits(class)
        && nrr_shared::ipc::ipc_operation_spec(op)
            .is_none_or(|spec| spec.allowed_clients.contains(&profile))
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
    use std::sync::atomic::{AtomicUsize, Ordering};
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
        /// Which of the two push phases the dispatcher reached.
        committed: AtomicUsize,
        abandoned: AtomicUsize,
    }

    impl ScriptedClient {
        fn new(outcome: ScriptedOutcome) -> Self {
            Self {
                outcome: StdMutex::new(Some(outcome)),
                last_call: StdMutex::new(None),
                committed: AtomicUsize::new(0),
                abandoned: AtomicUsize::new(0),
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
        fn subscribe_push(&self) -> Option<std::sync::mpsc::Receiver<serde_json::Value>> {
            let (_tx, rx) = std::sync::mpsc::sync_channel(1);
            // The sender is dropped with this call: the test only cares which
            // phase the dispatcher reaches, not what travels afterwards.
            Some(rx)
        }
        fn commit_push(&self) {
            self.committed.fetch_add(1, Ordering::SeqCst);
        }
        fn abandon_push(&self) {
            self.abandoned.fetch_add(1, Ordering::SeqCst);
        }
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
    fn a_confirmed_rules_update_invalidates_the_cached_snapshots() {
        use nrr_shared::ipc_payloads::MutationKind;
        let payload = serde_json::json!({ "mutation-kind": "rules-update", "dry-run": false });
        assert_eq!(
            mutation_kind_to_invalidate(IpcOperationName::MutationSubmit, &payload),
            Some(MutationKind::RulesUpdate)
        );
    }

    #[test]
    fn a_dry_run_invalidates_nothing() {
        // It changed nothing; dropping the cache would only cost a re-fetch.
        let payload = serde_json::json!({ "mutation-kind": "rules-update", "dry-run": true });
        assert_eq!(
            mutation_kind_to_invalidate(IpcOperationName::MutationSubmit, &payload),
            None
        );
    }

    #[test]
    fn a_read_operation_invalidates_nothing() {
        let payload = serde_json::json!({});
        assert_eq!(
            mutation_kind_to_invalidate(IpcOperationName::RulesList, &payload),
            None
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
    fn handle_request_routes_catalog_opcodes() {
        // Sanity check — every opcode added to the catalog resolves through
        // `from_slug` so the dispatcher forwards (does NOT emit
        // `unknown-operation`). Payload routing itself is exercised by the
        // handler-side integration tests; here we only verify
        // slug-recognition at the launcher boundary.
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
    fn handle_request_maps_confirmation_expired_code_to_its_slug() {
        // QML's review flows re-open the review on this slug.
        use nrr_ipc_client::IpcClientError;
        let client =
            ScriptedClient::new(ScriptedOutcome::ServerError(IpcClientError::ServerError {
                op: IpcOperationName::MutationSubmit,
                code: nrr_shared::ipc_transport::IpcErrorCode::ConfirmationExpired,
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

    fn forbidden() -> LauncherRpcResponse {
        LauncherRpcResponse::err("c-f", "forbidden", "refused".to_string())
    }

    fn open_to(op: IpcOperationName, profile: IpcClientProfile) -> bool {
        nrr_shared::ipc::ipc_operation_spec(op)
            .is_none_or(|spec| spec.allowed_clients.contains(&profile))
    }

    /// The tray asking for a GUI-only operation is refused for its surface;
    /// elevation cannot change that, so no UAC prompt and no relay.
    #[test]
    fn a_surface_refusal_is_not_relayed_through_the_broker() {
        let op = IpcOperationName::ApplyFailurePolicySet;
        assert!(!open_to(op, IpcClientProfile::TrayLightweight));
        let payload = serde_json::json!({});
        assert!(!broker_may_retry(
            op,
            &payload,
            IpcClientProfile::TrayLightweight,
            &forbidden()
        ));
        assert!(!broker_may_retry(
            IpcOperationName::MutationSubmit,
            &serde_json::json!({ "mutation-kind": "rules-update", "dry-run": false }),
            IpcClientProfile::AdminConsole,
            &forbidden()
        ));
    }

    #[test]
    fn no_operation_closed_to_the_tray_is_ever_relayed_for_it() {
        for op in IpcOperationName::ALL {
            if !open_to(op, IpcClientProfile::TrayLightweight) {
                assert!(
                    !broker_may_retry(
                        op,
                        &serde_json::json!({}),
                        IpcClientProfile::TrayLightweight,
                        &forbidden()
                    ),
                    "{}",
                    op.slug()
                );
            }
        }
    }

    /// Both elevation gates answer `Forbidden`: the class gate (a baseline
    /// mutation) and the by-value gate (a machine-wide setting actually changed).
    #[test]
    fn an_elevation_refusal_is_relayed_through_the_broker() {
        let submit = serde_json::json!({ "mutation-kind": "rules-update", "dry-run": false });
        for profile in [
            IpcClientProfile::GuiInteractive,
            IpcClientProfile::TrayLightweight,
        ] {
            assert!(open_to(IpcOperationName::MutationSubmit, profile));
            assert!(broker_may_retry(
                IpcOperationName::MutationSubmit,
                &submit,
                profile,
                &forbidden()
            ));
        }
        assert!(broker_may_retry(
            IpcOperationName::ApplyFailurePolicySet,
            &serde_json::json!({}),
            IpcClientProfile::GuiInteractive,
            &forbidden()
        ));
    }

    #[test]
    fn only_a_forbidden_answer_is_ever_retried() {
        let op = IpcOperationName::MutationSubmit;
        let payload = serde_json::json!({});
        let profile = IpcClientProfile::GuiInteractive;
        let ok = LauncherRpcResponse::ok("c-o", serde_json::json!({}));
        let other = LauncherRpcResponse::err("c-e", "rules-locked", "locked".to_string());
        assert!(!broker_may_retry(op, &payload, profile, &ok));
        assert!(!broker_may_retry(op, &payload, profile, &other));
    }

    #[test]
    fn each_surface_names_the_profile_the_service_admits_it_under() {
        use crate::launcher::LauncherSurface;
        assert_eq!(
            LauncherSurface::MainGui.client_profile(),
            IpcClientProfile::GuiInteractive
        );
        assert_eq!(
            LauncherSurface::Tray.client_profile(),
            IpcClientProfile::TrayLightweight
        );
    }

    fn lane_of(op: IpcOperationName, payload: serde_json::Value) -> RpcLane {
        let req = LauncherRpcRequest {
            correlation_id: format!("c-{}", op.slug()),
            operation: op.slug().to_string(),
            payload,
        };
        request_lane(&nrr_shared::launcher_rpc::encode_request_line(&req).unwrap())
    }

    /// The health probe must not queue behind a multi-second archive build.
    #[test]
    fn the_archive_export_has_a_lane_of_its_own() {
        assert_eq!(
            lane_of(
                IpcOperationName::DiagnosticsExportArchive,
                serde_json::json!({})
            ),
            RpcLane::Export
        );
        assert_eq!(
            lane_of(IpcOperationName::ServiceHealthGet, serde_json::json!({})),
            RpcLane::Side
        );
    }

    #[test]
    fn reads_take_the_side_lane_while_mutations_and_the_subscription_stay_on_main() {
        for op in [
            IpcOperationName::RulesList,
            IpcOperationName::SnapshotInitialGet,
            IpcOperationName::SnapshotInterfacesGet,
        ] {
            assert_eq!(
                lane_of(op, serde_json::json!({})),
                RpcLane::Side,
                "{}",
                op.slug()
            );
        }
        assert_eq!(
            lane_of(
                IpcOperationName::MutationSubmit,
                serde_json::json!({ "mutation-kind": "rules-update", "dry-run": false }),
            ),
            RpcLane::Main
        );
        assert_eq!(
            lane_of(
                IpcOperationName::StatusUpdatesSubscribe,
                serde_json::json!({})
            ),
            RpcLane::Main,
            "the subscribe call must stay on the connection that carries pushes"
        );
        assert_eq!(request_lane("not a request"), RpcLane::Main);
    }

    /// The safe-rollback token fetch is a read; the rollback it authorises
    /// is a mutation and keeps the ordered lane.
    #[test]
    fn the_rollback_dry_run_is_a_read_and_the_rollback_is_not() {
        assert_eq!(
            lane_of(
                IpcOperationName::RollbackRequest,
                serde_json::json!({ "dry-run": true })
            ),
            RpcLane::Side
        );
        assert_eq!(
            lane_of(
                IpcOperationName::RollbackRequest,
                serde_json::json!({ "dry-run": false, "_envelope_confirmation_token": "t" })
            ),
            RpcLane::Main
        );
    }

    /// The safe-rollback button sends the user's own rollback, which the
    /// service admits unelevated, so no UAC relay stands in its path; only the
    /// baseline form is one a `Forbidden` can send through the broker.
    #[test]
    fn only_the_baseline_rollback_needs_rights() {
        use nrr_shared::ipc_transport::canonical_operation_class;
        let own = serde_json::json!({ "dry-run": false, "_envelope_confirmation_token": "t" });
        let baseline = serde_json::json!({
            "dry-run": false,
            "admin-baseline": true,
            "_envelope_confirmation_token": "t",
        });
        let op = IpcOperationName::RollbackRequest;
        assert!(!canonical_operation_class(op, &own).requires_elevation());
        assert!(canonical_operation_class(op, &baseline).requires_elevation());
        assert!(broker_may_retry(
            op,
            &baseline,
            IpcClientProfile::GuiInteractive,
            &forbidden()
        ));
    }

    #[test]
    fn each_lane_opens_its_own_connection_once() {
        let mut clients = LaneClients::default();
        let opened = std::cell::Cell::new(0);
        let start = || -> Arc<dyn IpcClient> {
            opened.set(opened.get() + 1);
            Arc::new(ServiceStoppedClient)
        };
        let now = std::time::Instant::now();
        let (side, _) = clients.client_for(RpcLane::Side, now, start);
        let (export, _) = clients.client_for(RpcLane::Export, now, start);
        let (side_again, _) = clients.client_for(RpcLane::Side, now, start);
        assert!(Arc::ptr_eq(&side, &side_again));
        assert!(!Arc::ptr_eq(&side, &export));
        assert_eq!(opened.get(), 2);
    }

    #[test]
    fn the_main_lane_waits_for_its_client_only_while_it_is_young() {
        // The tray's startup subscribe was the first main-lane request, made
        // while the client it created was still connecting.
        let mut clients = LaneClients::default();
        let start = || -> Arc<dyn IpcClient> { Arc::new(ServiceStoppedClient) };
        let t0 = std::time::Instant::now();
        let (_, first) = clients.client_for(RpcLane::Main, t0, start);
        assert_eq!(first, CONNECT_BUDGET);
        let (_, later) = clients.client_for(RpcLane::Main, t0 + Duration::from_secs(2), start);
        assert_eq!(later, CONNECT_BUDGET - Duration::from_secs(2));
        let (_, settled) = clients.client_for(RpcLane::Main, t0 + Duration::from_secs(60), start);
        assert!(
            settled.is_zero(),
            "a settled main lane must fail a disconnect at once"
        );
        let (_, side) = clients.client_for(RpcLane::Side, t0, start);
        let (_, side_later) =
            clients.client_for(RpcLane::Side, t0 + Duration::from_secs(60), start);
        assert_eq!(side, CONNECT_BUDGET);
        assert_eq!(side_later, CONNECT_BUDGET, "side requests keep waiting");
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

    #[test]
    fn the_host_never_gives_up_before_the_dispatcher_answers() {
        let deadlines = host_answer_deadlines();
        for op in IpcOperationName::ALL {
            let host = deadlines.operations_ms[op.slug()];
            let dispatcher = dispatcher_answer_bound(op) + HOST_ANSWER_MARGIN;
            assert_eq!(u128::from(host), dispatcher.as_millis(), "{}", op.slug());
            assert!(
                u128::from(host) > (CONNECT_BUDGET + ipc_operation_timeout(op)).as_millis(),
                "{} must outlast the service call and the connect wait",
                op.slug()
            );
        }
        assert_eq!(
            deadlines.operations_ms.len(),
            IpcOperationName::ALL.len(),
            "one entry per operation, nothing else"
        );
    }

    /// Both surfaces must hand the launcher's table to their transport; a
    /// renamed key would silently fall back to the transport's own guess.
    #[test]
    fn both_surfaces_feed_the_answer_deadlines_to_their_transport() {
        use nrr_shared::launcher_rpc::HOST_ANSWER_DEADLINES_CONTEXT_KEY;
        let qml = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qml");
        for surface in ["Main.qml", "Tray.qml"] {
            let source = std::fs::read_to_string(qml.join(surface)).expect("read surface");
            let wiring = format!("nrrLaunchContext.{HOST_ANSWER_DEADLINES_CONTEXT_KEY}");
            assert!(source.contains(&wiring), "{surface} must pass {wiring}");
        }
        let transport =
            std::fs::read_to_string(qml.join("flows/RpcTransport.qml")).expect("read transport");
        for field in ["defaultMs", "operationsMs"] {
            assert!(
                transport.contains(field),
                "RpcTransport.qml must read {field}"
            );
        }
    }
}
