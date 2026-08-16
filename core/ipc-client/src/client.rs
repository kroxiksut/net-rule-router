//! `NamedPipeIpcClient` — sync request/response client.
//!
//! ## Threading model
//!
//! - **Caller thread:** invokes `client.call(operation, payload, timeout)`
//!   synchronously. Returns when the response arrives (or timeout).
//! - **Worker thread:** owned by the client. Drains pending requests
//!   from a `mpsc::sync_channel`, writes them on the pipe, reads the
//!   response, dispatches it to the originating caller via the
//!   per-request `oneshot` channel.
//! - **State guard:** an `Arc<RwLock<ConnectionStatus>>` lets any thread
//!   read the current connection status without blocking the worker.
//!
//! Concurrent calls from multiple threads are serialised through the
//! single worker thread. We do not pipeline requests on the same
//! connection (one in-flight at a time) — simpler than tracking
//! per-`request_id` correlation, and the round-trip time on a local
//! pipe is already < 1ms.
//!
//! ## Reconnect
//!
//! Worker thread state machine:
//!
//! 1. **Disconnected**: invoke `transport::connect()`. On success →
//!    Connecting. On failure → consult `scm_probe::probe()` to decide
//!    if we drop into NotInstalled / ServiceStopped, then back off.
//! 2. **Connecting**: send `ContractNegotiate`, expect ack. On success →
//!    Connected. On version mismatch → ProtocolMismatch (terminal).
//! 3. **Connected**: drain pending requests until error / EOF / shutdown.
//!    On read error → close handle, transition to Disconnected.
//! 4. **NotInstalled / ServiceStopped**: poll SCM at `slow` backoff.
//!    Transition to Disconnected when SCM reports Running / StartPending.
//!
//! Pending requests held in the queue at the moment of disconnect get
//! `Err(IpcClientError::Disconnected)` so callers don't hang.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use nrr_shared::ipc::IpcOperationName;

use crate::connection::{ConnectionStatus, IpcClientError, NegotiateInfo, ReconnectBackoff};
use crate::protocol::{
    build_contract_negotiate, build_request_envelope, interpret_negotiate_response,
    new_request_serial, parse_response, NegotiateParse, RequestResponse, CLIENT_PROTOCOL_VERSION,
};
use crate::scm_probe::{self, ServiceProbe};
use crate::transport::{self, PipeIo, SendableHandle};
use crate::wire::{read_frame, write_frame};

/// Capacity of the per-request channel between caller threads and the
/// worker thread. 32 is generous for GUI / Tray traffic.
const REQUEST_CHANNEL_CAPACITY: usize = 32;

// ── Public client ────────────────────────────────────────────────────────────

/// Sync IPC client. Cheap to clone — internal state lives behind `Arc`.
#[derive(Clone)]
pub struct NamedPipeIpcClient {
    inner: Arc<ClientInner>,
}

impl NamedPipeIpcClient {
    /// Spawn a worker thread that maintains the connection in the
    /// background. Returns immediately; status starts as `Disconnected`.
    pub fn start() -> Self {
        let inner = Arc::new(ClientInner::new());
        let inner_for_worker = Arc::clone(&inner);
        // Failing to spawn the single client worker thread at startup is fatal
        // and unrecoverable — there is no degraded mode without it.
        #[allow(clippy::expect_used)]
        let handle = thread::Builder::new()
            .name("nrr-ipc-client".into())
            .spawn(move || worker_loop(inner_for_worker))
            .expect("spawn ipc client worker");
        if let Ok(mut g) = inner.worker_handle.lock() {
            *g = Some(handle);
        }
        Self { inner }
    }

    /// Current connection status. Cheap RwLock read.
    pub fn connection_status(&self) -> ConnectionStatus {
        self.inner
            .status
            .read()
            .map(|g| g.clone())
            .unwrap_or(ConnectionStatus::Disconnected {
                last_error: "client status lock poisoned".into(),
            })
    }

    /// Submit one operation; block up to `timeout` waiting for a response.
    ///
    /// Errors:
    /// - `Disconnected` — client isn't connected. Caller may show fallback UI.
    /// - `Timeout` — server didn't reply in time.
    /// - `ServerError(...)` — server returned a structured error envelope.
    pub fn call(
        &self,
        operation: IpcOperationName,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, IpcClientError> {
        if !self.connection_status().is_connected() {
            return Err(IpcClientError::Disconnected);
        }

        let request_id = format!("req-{}", new_request_serial());
        let envelope = build_request_envelope(operation, &request_id, payload);

        let (tx, rx) = sync_channel::<RequestResponse>(1);
        let pending = PendingRequest {
            envelope,
            response_tx: tx,
        };

        if self.inner.request_tx.try_send(pending).is_err() {
            return Err(IpcClientError::Disconnected);
        }

        match rx.recv_timeout(timeout) {
            Ok(RequestResponse::Ok(payload)) => Ok(payload),
            Ok(RequestResponse::ServerError { op, code, message }) => {
                Err(IpcClientError::ServerError { op, code, message })
            }
            Ok(RequestResponse::BadResponse(reason)) => Err(IpcClientError::BadResponse { reason }),
            Ok(RequestResponse::Disconnected) => Err(IpcClientError::Disconnected),
            Err(RecvTimeoutError::Timeout) => Err(IpcClientError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(IpcClientError::ClientShutdown),
        }
    }

    /// Force the worker to drop the current connection and reconnect.
    /// Used by GUI "Retry connection" button.
    pub fn force_reconnect(&self) {
        self.inner.force_reconnect.store(true, Ordering::SeqCst);
    }

    /// Snapshot of the most recent successful `ContractNegotiate` handshake.
    /// `None` until the first handshake completes; never cleared back to
    /// `None` — a stale negotiate from a previous service binary is still
    /// useful for the compatibility banner.
    pub fn negotiate_info(&self) -> Option<NegotiateInfo> {
        self.inner
            .negotiate_info
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    /// Register a push-frame receiver. Only one subscriber per client is
    /// supported; calling twice replaces
    /// the previous channel (previous subscriber's `Receiver` becomes
    /// disconnected). Push frames arrive as the parsed JSON `payload`
    /// value of the response envelope (`StatusUpdatePushFrame`).
    ///
    /// Bounded channel capacity 64 — the GUI generally drains push
    /// frames within ms; this is just slack for transient bursts. On
    /// overflow the worker drops new frames and logs.
    pub fn subscribe_push(&self) -> std::sync::mpsc::Receiver<Value> {
        let (tx, rx) = sync_channel::<Value>(64);
        if let Ok(mut g) = self.inner.push_tx.lock() {
            *g = Some(tx);
        }
        rx
    }

    /// Trigger client shutdown. Worker thread exits, in-flight requests
    /// receive `Disconnected`. Idempotent.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }
}

impl crate::connection::IpcClient for NamedPipeIpcClient {
    fn call(
        &self,
        operation: IpcOperationName,
        payload: Value,
        timeout: Duration,
    ) -> Result<Value, IpcClientError> {
        Self::call(self, operation, payload, timeout)
    }

    fn connection_status(&self) -> ConnectionStatus {
        Self::connection_status(self)
    }

    fn force_reconnect(&self) {
        Self::force_reconnect(self);
    }

    fn subscribe_push(&self) -> Option<std::sync::mpsc::Receiver<Value>> {
        Some(Self::subscribe_push(self))
    }

    fn negotiate_info(&self) -> Option<NegotiateInfo> {
        Self::negotiate_info(self)
    }

    fn active_subscription_id(&self) -> Option<String> {
        self.inner
            .subscription_id
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }
}

impl Drop for NamedPipeIpcClient {
    fn drop(&mut self) {
        // Only the *last* Arc holder triggers shutdown.
        if Arc::strong_count(&self.inner) == 1 {
            self.shutdown();
            if let Ok(mut g) = self.inner.worker_handle.lock() {
                if let Some(h) = g.take() {
                    let _ = h.join();
                }
            }
        }
    }
}

// ── Internal types ───────────────────────────────────────────────────────────

struct ClientInner {
    status: RwLock<ConnectionStatus>,
    request_tx: SyncSender<PendingRequest>,
    request_rx: Mutex<Option<Receiver<PendingRequest>>>,
    shutdown: AtomicBool,
    force_reconnect: AtomicBool,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
    /// Push channel sender, set once the client subscribes via
    /// [`NamedPipeIpcClient::subscribe_push`]. Push frames seen on the wire
    /// (`request_id == ""`) are forwarded here; if `None`, they are dropped.
    push_tx: Mutex<Option<SyncSender<Value>>>,
    /// Last successful `ContractNegotiate` response payload (server protocol
    /// + service semver), feeding the GUI's compatibility banner.
    negotiate_info: RwLock<Option<NegotiateInfo>>,
    /// Envelope of the last accepted status subscription, replayed after a
    /// reconnect. A subscription belongs to the pipe connection, so a caller
    /// that subscribed once and went quiet (the tray) would otherwise stay
    /// silently unsubscribed for the rest of its life.
    last_subscribe: Mutex<Option<Value>>,
    /// Id the SERVER allocated for the live subscription. Re-read (not cached)
    /// by whoever labels forwarded push frames, because a replay after a
    /// reconnect creates a new subscription with a new id.
    subscription_id: Mutex<Option<String>>,
    /// Counter behind the replayed subscription's `request-id`, so a replay
    /// never collides with an in-flight caller request.
    replay_seq: AtomicU64,
}

// `NegotiateInfo` is declared in `connection.rs` so the `IpcClient`
// trait can include the getter in its default method (block
// 16.QoL+7). Re-export it from this module for callers that grab
// it via the concrete `NamedPipeIpcClient` rather than the trait.

impl ClientInner {
    fn new() -> Self {
        let (tx, rx) = sync_channel::<PendingRequest>(REQUEST_CHANNEL_CAPACITY);
        Self {
            status: RwLock::new(ConnectionStatus::Disconnected {
                last_error: "client just started".into(),
            }),
            request_tx: tx,
            request_rx: Mutex::new(Some(rx)),
            shutdown: AtomicBool::new(false),
            force_reconnect: AtomicBool::new(false),
            worker_handle: Mutex::new(None),
            push_tx: Mutex::new(None),
            negotiate_info: RwLock::new(None),
            last_subscribe: Mutex::new(None),
            subscription_id: Mutex::new(None),
            replay_seq: AtomicU64::new(0),
        }
    }

    fn set_status(&self, s: ConnectionStatus) {
        if let Ok(mut g) = self.status.write() {
            *g = s;
        }
    }
}

struct PendingRequest {
    envelope: Value,
    response_tx: SyncSender<RequestResponse>,
}

// ── Worker loop ──────────────────────────────────────────────────────────────

fn worker_loop(inner: Arc<ClientInner>) {
    let request_rx = match inner.request_rx.lock() {
        Ok(mut g) => match g.take() {
            Some(r) => r,
            None => return,
        },
        Err(_) => return,
    };

    let mut backoff = ReconnectBackoff::fast();
    let mut slow_backoff = ReconnectBackoff::slow();

    while !inner.shutdown.load(Ordering::SeqCst) {
        // Try to connect.
        inner.set_status(ConnectionStatus::Connecting);
        let pipe = match transport::connect() {
            Ok(h) => SendableHandle(h),
            Err(code) => {
                handle_connect_failure(&inner, code, &mut backoff, &mut slow_backoff);
                continue;
            }
        };

        // Handshake: ContractNegotiate.
        match handshake(&pipe) {
            HandshakeResult::Ok(info) => {
                // Cache the parsed negotiate body before flipping to Connected
                // so any reader reacting to the status transition sees it.
                if let Ok(mut g) = inner.negotiate_info.write() {
                    *g = Some(info);
                }
                inner.set_status(ConnectionStatus::Connected);
                backoff.reset();
                slow_backoff.reset();
            }
            HandshakeResult::ProtocolMismatch { server_version } => {
                transport::close_pipe(pipe.0);
                inner.set_status(ConnectionStatus::ProtocolMismatch {
                    server_version,
                    client_version: CLIENT_PROTOCOL_VERSION,
                });
                // Terminal: stop reconnect attempts. Wait for shutdown
                // signal (block on request channel with periodic checks).
                wait_for_shutdown_or_force_reconnect(&inner, &request_rx);
                continue;
            }
            HandshakeResult::TransportError(reason) => {
                transport::close_pipe(pipe.0);
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("handshake failed: {reason}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        }

        // Connected: serve requests until disconnect.
        serve_requests(&inner, &request_rx, pipe);
    }

    // Drain any remaining pending requests on shutdown.
    while let Ok(p) = request_rx.try_recv() {
        let _ = p.response_tx.send(RequestResponse::Disconnected);
    }
}

fn handle_connect_failure(
    inner: &Arc<ClientInner>,
    last_code: u32,
    fast: &mut ReconnectBackoff,
    slow: &mut ReconnectBackoff,
) {
    // Decide between fast retry vs slow SCM-aware polling.
    let probe = scm_probe::probe();
    let (status, delay) = match probe {
        ServiceProbe::NotFound => (ConnectionStatus::NotInstalled, slow.next_delay()),
        ServiceProbe::Stopped => (ConnectionStatus::ServiceStopped, slow.next_delay()),
        ServiceProbe::StartPending | ServiceProbe::StopPending => {
            (ConnectionStatus::Connecting, Duration::from_millis(500))
        }
        ServiceProbe::Running | ServiceProbe::Unknown { .. } => (
            ConnectionStatus::Disconnected {
                last_error: format!("connect failed (Win32 0x{last_code:08X})"),
            },
            fast.next_delay(),
        ),
    };
    inner.set_status(status);
    sleep_observing_shutdown(inner, delay);
}

enum HandshakeResult {
    Ok(NegotiateInfo),
    ProtocolMismatch { server_version: u32 },
    TransportError(String),
}

fn handshake(pipe: &SendableHandle) -> HandshakeResult {
    // No progress printing here. This library runs inside binaries whose stdout
    // and stderr ARE their interface — the console's output is what a script
    // reads — so a stray line from the transport is output nobody asked for.
    // Every failure below already travels back as a typed `TransportError`,
    // which the caller renders where it belongs.
    let request = build_contract_negotiate(CLIENT_PROTOCOL_VERSION);
    let mut io = match PipeIo::new(pipe.0) {
        Ok(io) => io,
        Err(e) => return HandshakeResult::TransportError(e.to_string()),
    };
    if let Err(e) = write_frame(&mut io, &request) {
        return HandshakeResult::TransportError(e.to_string());
    }
    let response: Value = match read_frame(&mut io) {
        Ok(r) => r,
        Err(e) => return HandshakeResult::TransportError(e.to_string()),
    };

    // Interpretation of the negotiate frame is transport-neutral — shared with
    // the Unix client via `crate::protocol`. Only the I/O above is per-transport.
    match interpret_negotiate_response(&response) {
        NegotiateParse::Ok(info) => HandshakeResult::Ok(info),
        NegotiateParse::ProtocolMismatch { server_version } => {
            HandshakeResult::ProtocolMismatch { server_version }
        }
        NegotiateParse::Unexpected(msg) => HandshakeResult::TransportError(msg),
    }
}

fn serve_requests(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
    pipe: SendableHandle,
) {
    let pipe_handle = pipe.0;
    let mut io = match PipeIo::new(pipe_handle) {
        Ok(io) => io,
        Err(e) => {
            eprintln!("nrr-ipc-client: serve_requests PipeIo::new failed: {e}");
            transport::close_pipe(pipe_handle);
            inner.set_status(ConnectionStatus::Disconnected {
                last_error: format!("serve_requests PipeIo init: {e}"),
            });
            return;
        }
    };

    // A subscription lives and dies with the pipe connection, so the client
    // that owns reconnect owns restoring it — callers subscribe once.
    replay_subscription(inner, &mut io);

    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }

        // Pull next request with a small timeout so we re-check shutdown.
        let pending = match request_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => p,
            Err(RecvTimeoutError::Timeout) => {
                // Idle tick. A subscriber's push frames arrive whenever the
                // service decides, not when we happen to be mid-request, so
                // drain them here — otherwise a client that subscribes and
                // then goes quiet (the tray does exactly that) never reads a
                // single event and the subscription is silently useless.
                if !drain_push_frames(inner, &mut io) {
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };

        if let Err(e) = write_frame(&mut io, &pending.envelope) {
            // Transport dead — fail this request and break to reconnect.
            let _ = pending.response_tx.send(RequestResponse::Disconnected);
            inner.set_status(ConnectionStatus::Disconnected {
                last_error: format!("write failed: {e}"),
            });
            break;
        }

        // Read frames in a loop until we find one whose `request_id` matches
        // ours. Frames with empty `request_id` are push frames and get
        // routed to the push channel; frames with a mismatched request_id
        // are discarded with a warning (shouldn't happen on a healthy
        // single-in-flight pipe).
        // Wire envelope serialises with `rename_all = "kebab-case"` so
        // the JSON field name is `request-id`, NOT snake_case. The
        // envelope we built locally uses `request-id` (see
        // `build_request_envelope`) — read it back with the same key.
        // Fallback to snake_case is defensive for older payload shapes.
        let request_id = pending
            .envelope
            .get("request-id")
            .or_else(|| pending.envelope.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut transport_dead = false;
        loop {
            let frame: Value = match read_frame(&mut io) {
                Ok(r) => r,
                Err(e) => {
                    let _ = pending.response_tx.send(RequestResponse::Disconnected);
                    inner.set_status(ConnectionStatus::Disconnected {
                        last_error: format!("read failed: {e}"),
                    });
                    transport_dead = true;
                    break;
                }
            };
            // Same kebab-case wire key as `request_id` above; server
            // uses `IpcResponseEnvelope` which carries `request-id`.
            let frame_request_id = frame
                .get("request-id")
                .or_else(|| frame.get("request_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if frame_request_id.is_empty() {
                route_push_frame(inner, &frame, "inline");
                continue;
            }
            if frame_request_id == request_id {
                let parsed = parse_response(&frame);
                if matches!(parsed, RequestResponse::Ok(_)) {
                    remember_subscription(inner, &pending.envelope);
                    if is_subscribe_envelope(&pending.envelope) {
                        remember_subscription_id(inner, &frame);
                    }
                }
                let _ = pending.response_tx.send(parsed);
                break;
            }
            // Mismatched request_id on the wire — log and continue.
            eprintln!(
                "nrr-ipc-client: discarding frame with unexpected request_id={frame_request_id}",
            );
        }
        if transport_dead {
            break;
        }
    }

    transport::close_pipe(pipe_handle);
}

/// Read every complete frame already buffered on the pipe and route the push
/// frames among them to the subscriber. Called only when no request is in
/// flight, so any frame found here is server-initiated.
///
/// Returns `false` when the transport died and the caller must reconnect.
///
/// Only frames whose length prefix is already present are read: the peek
/// guarantees we never enter a blocking read on an idle pipe, which would
/// stall the next outgoing request for as long as the service stays quiet.
fn drain_push_frames(inner: &Arc<ClientInner>, io: &mut PipeIo) -> bool {
    loop {
        match io.peek_available() {
            // Fewer than four bytes cannot even carry a length prefix; leave
            // the partial frame for the next tick.
            Ok(available) if available < 4 => return true,
            Ok(_) => {}
            Err(e) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("peek failed: {e}"),
                });
                return false;
            }
        }
        let frame: Value = match read_frame(io) {
            Ok(f) => f,
            Err(e) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("idle read failed: {e}"),
                });
                return false;
            }
        };
        let frame_request_id = frame
            .get("request-id")
            .or_else(|| frame.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !frame_request_id.is_empty() {
            // A response with nothing waiting for it — the request that owned
            // it is long gone. Dropping it is the only sane action, but it
            // means the two ends disagree about what is in flight.
            eprintln!(
                "nrr-ipc-client: discarding unsolicited response frame request_id={frame_request_id}",
            );
            continue;
        }
        route_push_frame(inner, &frame, "idle");
    }
}

/// True when this request envelope is a status subscription.
fn is_subscribe_envelope(envelope: &Value) -> bool {
    envelope
        .get("operation")
        .and_then(|v| v.as_str())
        .map(|op| op == IpcOperationName::StatusUpdatesSubscribe.slug())
        .unwrap_or(false)
}

/// Remember an accepted subscription request so it can be replayed on the
/// next connection.
fn remember_subscription(inner: &Arc<ClientInner>, envelope: &Value) {
    if !is_subscribe_envelope(envelope) {
        return;
    }
    if let Ok(mut g) = inner.last_subscribe.lock() {
        *g = Some(envelope.clone());
    }
}

/// Record the id the server allocated for the subscription just accepted. Every
/// accepted subscribe — the caller's first one and each replay after a
/// reconnect — gets a fresh id, so this is overwritten, never appended to.
fn remember_subscription_id(inner: &Arc<ClientInner>, frame: &Value) {
    let id = frame
        .get("payload")
        .and_then(|p| {
            p.get("subscription-id")
                .or_else(|| p.get("subscription_id"))
        })
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    if id.is_none() {
        return;
    }
    if let Ok(mut g) = inner.subscription_id.lock() {
        *g = id;
    }
}

/// Re-issue the remembered subscription on a freshly opened pipe. Runs before
/// the dispatch loop so events emitted right after reconnect are not missed.
fn replay_subscription(inner: &Arc<ClientInner>, io: &mut PipeIo) {
    let Ok(guard) = inner.last_subscribe.lock() else {
        return;
    };
    let Some(envelope) = guard.as_ref() else {
        return;
    };
    let mut replay = envelope.clone();
    let seq = inner.replay_seq.fetch_add(1, Ordering::SeqCst);
    let request_id = format!("resubscribe-{seq}");
    replay["request-id"] = Value::String(request_id.clone());
    drop(guard);

    if let Err(e) = write_frame(io, &replay) {
        eprintln!("nrr-ipc-client: resubscribe write failed: {e}");
        return;
    }
    // Read until the matching response arrives; push frames may already be
    // queued ahead of it and must not be discarded.
    loop {
        let frame: Value = match read_frame(io) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("nrr-ipc-client: resubscribe read failed: {e}");
                return;
            }
        };
        let frame_request_id = frame
            .get("request-id")
            .or_else(|| frame.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if frame_request_id.is_empty() {
            route_push_frame(inner, &frame, "resubscribe");
            continue;
        }
        if frame_request_id == request_id {
            let ok = frame.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
            if ok {
                // The server allocated a NEW subscription for this connection;
                // the id from the caller's original subscribe is dead.
                remember_subscription_id(inner, &frame);
            }
            eprintln!(
                "nrr-ipc-client: resubscribed after reconnect, ok={ok} (subscription={})",
                inner
                    .subscription_id
                    .lock()
                    .ok()
                    .and_then(|g| g.clone())
                    .unwrap_or_else(|| "unknown".to_string())
            );
            return;
        }
    }
}

/// Hand a server-initiated frame to the subscriber. Every outcome is
/// reported: a silently dropped push is indistinguishable from one that
/// never arrived, and that ambiguity has cost us two test runs.
fn route_push_frame(inner: &Arc<ClientInner>, frame: &Value, source: &str) {
    let Some(payload) = frame.get("payload").cloned() else {
        eprintln!("nrr-ipc-client: push frame without payload (source={source})");
        return;
    };
    let event_type = payload
        .get("event")
        .and_then(|e| e.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let Ok(guard) = inner.push_tx.lock() else {
        eprintln!("nrr-ipc-client: push {event_type} lost — subscriber lock poisoned");
        return;
    };
    let Some(tx) = guard.as_ref() else {
        eprintln!("nrr-ipc-client: push {event_type} discarded — nobody subscribed");
        return;
    };
    match tx.try_send(payload) {
        Ok(()) => eprintln!("nrr-ipc-client: push {event_type} delivered (source={source})"),
        Err(e) => eprintln!("nrr-ipc-client: push {event_type} dropped — channel full ({e})"),
    }
}

fn wait_for_shutdown_or_force_reconnect(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
) {
    while !inner.shutdown.load(Ordering::SeqCst) {
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }
        // Drain any pending requests so callers don't hang.
        match request_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(p) => {
                let _ = p.response_tx.send(RequestResponse::Disconnected);
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn sleep_observing_shutdown(inner: &Arc<ClientInner>, total: Duration) {
    let granularity = Duration::from_millis(50);
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if inner.shutdown.load(Ordering::SeqCst) {
            return;
        }
        // Consume the flag (swap, not load) when waking early for it. Every
        // other reader (`serve_requests`, `wait_for_shutdown_or_force_reconnect`)
        // already swaps-and-clears on observing it; this was the one reader
        // that only peeked. A `force_reconnect()` nudge fired while the worker
        // was backing off (the common case: a caller's failed `call()` nudges
        // on every `Disconnected`, and backoff is where the worker spends most
        // of its time before the service comes back) left the flag set. The
        // NEXT successful connect then hit `serve_requests`' own top-of-loop
        // check, which read it still `true` and broke immediately — tearing
        // down the connection before serving a single request, without even
        // resetting `status` off `Connected`. Any subsequent failed call
        // nudges again, so the cycle never broke on its own: the worker kept
        // reconnecting and immediately self-disconnecting, forever, while
        // `connection_status()` reported `Connected` for a fraction of each
        // cycle far too small for a caller's synchronous check to observe.
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(remaining.min(granularity));
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // The transport-neutral protocol helpers (envelope building, operation-class
    // resolution, handshake/response parsing) live in `crate::protocol` and are
    // tested there. Only the Windows client's own lifecycle behaviour is
    // exercised here.

    #[test]
    fn call_returns_disconnected_when_status_not_connected() {
        // Client just started → status is Disconnected. Calling
        // immediately should return Disconnected (we don't try to
        // produce a real pipe in this unit test).
        let client = NamedPipeIpcClient::start();
        let result = client.call(
            IpcOperationName::ServiceHealthGet,
            serde_json::json!({}),
            Duration::from_millis(50),
        );
        assert!(matches!(result, Err(IpcClientError::Disconnected)));
        client.shutdown();
    }

    #[test]
    fn force_reconnect_does_not_panic() {
        let client = NamedPipeIpcClient::start();
        client.force_reconnect();
        assert!(
            client.connection_status().is_reconnecting()
                || matches!(
                    client.connection_status(),
                    ConnectionStatus::ServiceStopped | ConnectionStatus::NotInstalled
                )
        );
        client.shutdown();
    }

    // Regression: a `force_reconnect()` nudge fired while the worker was
    // backing off must not survive the early wake-up it causes.
    // `sleep_observing_shutdown` has to consume the flag, not just read it —
    // otherwise a stale `true` tears down the next successful
    // `serve_requests()` before it serves a single request, livelocking the
    // client between "reconnect" and "instant disconnect" whenever a caller
    // keeps nudging on every failed call.
    #[test]
    fn sleep_observing_shutdown_consumes_force_reconnect_flag() {
        let inner = Arc::new(ClientInner::new());
        inner.force_reconnect.store(true, Ordering::SeqCst);

        let started = Instant::now();
        sleep_observing_shutdown(&inner, Duration::from_secs(10));

        // Woke early because of the flag, not because the 10s elapsed.
        assert!(started.elapsed() < Duration::from_secs(1));
        // The flag must be cleared — otherwise the caller's next
        // `serve_requests()` cycle observes it as a second, unintended
        // "force reconnect now" and self-disconnects immediately.
        assert!(!inner.force_reconnect.load(Ordering::SeqCst));
    }

    // A stale flag from a nudge that landed while backing off must not
    // survive into the connected phase: `serve_requests`'s own top-of-loop
    // check already swaps-and-clears, so simulating "the flag was left set
    // and then a fresh serve_requests cycle starts" must observe `false`
    // after `sleep_observing_shutdown` ran in between, not the stale `true`.
    #[test]
    fn sleep_observing_shutdown_does_not_busy_spin_without_the_flag() {
        let inner = Arc::new(ClientInner::new());
        let started = Instant::now();
        sleep_observing_shutdown(&inner, Duration::from_millis(150));
        assert!(started.elapsed() >= Duration::from_millis(120));
    }

    #[test]
    fn shutdown_is_idempotent() {
        let client = NamedPipeIpcClient::start();
        client.shutdown();
        client.shutdown(); // no panic
    }
}
