//! `UnixIpcClient`: sync request/response client over `AF_UNIX`, the Linux
//! sibling of the Windows [`crate::client::NamedPipeIpcClient`].
//!
//! ## What is shared vs per-OS
//!
//! The *protocol* (envelope shape, operation-class resolution, handshake /
//! response parsing) is the neutral [`crate::protocol`] layer — one definition,
//! used by both clients. The *connection state machine* types
//! (`ConnectionStatus`, `ReconnectBackoff`, the `IpcClient` trait) are the
//! already-cross-platform [`crate::connection`]. What differs, and lives here,
//! is the *mechanism*: the byte carrier is a `UnixStream` (which is already
//! `Read + Write + Send`, so no `PipeIo`/overlapped adapter is needed), and the
//! reconnect loop has no SCM probe — on Linux the service is a systemd unit, so
//! a failed connect just backs off and retries.
//!
//! ## Threading model (identical to the Windows client)
//!
//! One owned worker thread drains a bounded request channel, writes each request
//! on the socket, reads the matching response, and dispatches it back to the
//! caller. Concurrent `call()`s from multiple threads serialise through the
//! single worker (one in-flight request at a time).
//!
//! ## Testing
//!
//! The transport-generic `negotiate_over` / `exchange` helpers are unit-tested
//! against an `AF_UNIX` `socketpair`, and the whole client is driven end-to-end
//! against a local `UnixListener` stub server (handshake + round-trip +
//! reconnect) on WSL2 — no real service needed. The production server side
//! (`SO_PEERCRED` peer-credential identity in a future `linux-service`) is out
//! of scope for this slice.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

use nrr_shared::ipc::IpcOperationName;
use nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;

use crate::connection::{ConnectionStatus, IpcClientError, NegotiateInfo, ReconnectBackoff};
use crate::protocol::{
    build_contract_negotiate, build_request_envelope, interpret_negotiate_response,
    new_request_serial, parse_response, NegotiateParse, RequestResponse, CLIENT_PROTOCOL_VERSION,
};
use crate::transport_unix;
use crate::wire::{read_frame, write_frame, WireError};

/// Capacity of the per-request channel between caller threads and the worker.
const REQUEST_CHANNEL_CAPACITY: usize = 32;

// ── Public client ────────────────────────────────────────────────────────────

/// Sync `AF_UNIX` IPC client. Cheap to clone — state lives behind `Arc`.
#[derive(Clone)]
pub struct UnixIpcClient {
    inner: Arc<ClientInner>,
}

impl UnixIpcClient {
    /// Spawn a worker that maintains the connection to the service's canonical
    /// endpoint ([`SERVICE_ENDPOINT_ADDRESS`]) in the background. Returns
    /// immediately; status starts as `Disconnected`.
    pub fn start() -> Self {
        Self::start_at(PathBuf::from(SERVICE_ENDPOINT_ADDRESS))
    }

    /// Spawn a worker connecting to an arbitrary socket path. Used by tests to
    /// drive the client against a temp-path stub listener instead of the
    /// root-owned production socket.
    fn start_at(endpoint: PathBuf) -> Self {
        let inner = Arc::new(ClientInner::new(endpoint));
        let inner_for_worker = Arc::clone(&inner);
        // Failing to spawn the single worker at startup is fatal and
        // unrecoverable — there is no degraded mode without it.
        #[allow(clippy::expect_used)]
        let handle = thread::Builder::new()
            .name("nrr-ipc-client-unix".into())
            .spawn(move || worker_loop(inner_for_worker))
            .expect("spawn unix ipc client worker");
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

    /// Submit one operation; block up to `timeout` for a response.
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
    pub fn force_reconnect(&self) {
        self.inner.force_reconnect.store(true, Ordering::SeqCst);
    }

    /// Snapshot of the most recent successful `ContractNegotiate` handshake.
    pub fn negotiate_info(&self) -> Option<NegotiateInfo> {
        self.inner
            .negotiate_info
            .read()
            .ok()
            .and_then(|g| g.clone())
    }

    /// Register a push-frame receiver (server-pushed `StatusUpdate` frames).
    /// One subscriber per client; calling twice replaces the previous channel.
    pub fn subscribe_push(&self) -> Receiver<Value> {
        let (tx, rx) = sync_channel::<Value>(64);
        if let Ok(mut g) = self.inner.push_tx.lock() {
            *g = Some(tx);
        }
        rx
    }

    /// Trigger client shutdown. Idempotent.
    pub fn shutdown(&self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
    }
}

impl crate::connection::IpcClient for UnixIpcClient {
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

    fn subscribe_push(&self) -> Option<Receiver<Value>> {
        Some(Self::subscribe_push(self))
    }

    fn negotiate_info(&self) -> Option<NegotiateInfo> {
        Self::negotiate_info(self)
    }
}

impl Drop for UnixIpcClient {
    fn drop(&mut self) {
        // Only the *last* Arc holder triggers shutdown + join.
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

// ── Internal state ───────────────────────────────────────────────────────────

struct ClientInner {
    endpoint: PathBuf,
    status: RwLock<ConnectionStatus>,
    request_tx: SyncSender<PendingRequest>,
    request_rx: Mutex<Option<Receiver<PendingRequest>>>,
    shutdown: AtomicBool,
    force_reconnect: AtomicBool,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
    push_tx: Mutex<Option<SyncSender<Value>>>,
    negotiate_info: RwLock<Option<NegotiateInfo>>,
    /// Envelope of the last accepted status subscription, replayed after a
    /// reconnect. A subscription belongs to the socket connection, so a caller
    /// that subscribed once and went quiet (the tray) would otherwise stay
    /// silently unsubscribed for the rest of its life.
    last_subscribe: Mutex<Option<Value>>,
    /// Counter behind the replayed subscription's `request-id`, so a replay
    /// never collides with an in-flight caller request.
    replay_seq: AtomicU64,
}

impl ClientInner {
    fn new(endpoint: PathBuf) -> Self {
        let (tx, rx) = sync_channel::<PendingRequest>(REQUEST_CHANNEL_CAPACITY);
        Self {
            endpoint,
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

    while !inner.shutdown.load(Ordering::SeqCst) {
        inner.set_status(ConnectionStatus::Connecting);
        let mut stream = match transport_unix::connect_to(&inner.endpoint) {
            Ok(s) => s,
            Err(e) => {
                // No SCM probe on Linux — the service is a systemd unit. Just
                // back off and retry; systemd owns start/stop.
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("connect failed: {e}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        };

        // Handshake: ContractNegotiate. Interpretation is neutral (protocol).
        let parsed = match negotiate_over(&mut stream) {
            Ok(p) => p,
            Err(e) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("handshake failed: {e}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        };
        match parsed {
            NegotiateParse::Ok(info) => {
                if let Ok(mut g) = inner.negotiate_info.write() {
                    *g = Some(info);
                }
                inner.set_status(ConnectionStatus::Connected);
                backoff.reset();
            }
            NegotiateParse::ProtocolMismatch { server_version } => {
                inner.set_status(ConnectionStatus::ProtocolMismatch {
                    server_version,
                    client_version: CLIENT_PROTOCOL_VERSION,
                });
                // Terminal: stop reconnecting until shutdown / force-reconnect.
                wait_for_shutdown_or_force_reconnect(&inner, &request_rx);
                continue;
            }
            NegotiateParse::Unexpected(msg) => {
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("handshake rejected: {msg}"),
                });
                let delay = backoff.next_delay();
                sleep_observing_shutdown(&inner, delay);
                continue;
            }
        }

        serve_requests(&inner, &request_rx, &mut stream);
    }

    // Drain any remaining pending requests on shutdown.
    while let Ok(p) = request_rx.try_recv() {
        let _ = p.response_tx.send(RequestResponse::Disconnected);
    }
}

fn serve_requests(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
    stream: &mut std::os::unix::net::UnixStream,
) {
    // A subscription lives and dies with the socket connection, so the side
    // that owns reconnect owns restoring it — callers subscribe once.
    if !replay_subscription(inner, stream) {
        return;
    }

    loop {
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }

        // Pull the next request with a small timeout so we re-check shutdown /
        // force-reconnect while idle.
        let pending = match request_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(p) => p,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        let request_id = pending
            .envelope
            .get("request-id")
            .or_else(|| pending.envelope.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let push = |frame: &Value| route_push_frame(inner, frame, "inline");

        match exchange(stream, &pending.envelope, &request_id, &push) {
            Ok(resp) => {
                if matches!(resp, RequestResponse::Ok(_)) {
                    remember_subscription(inner, &pending.envelope);
                }
                let _ = pending.response_tx.send(resp);
            }
            Err(e) => {
                // Transport dead — fail this request and break to reconnect.
                let _ = pending.response_tx.send(RequestResponse::Disconnected);
                inner.set_status(ConnectionStatus::Disconnected {
                    last_error: format!("exchange failed: {e}"),
                });
                break;
            }
        }
    }
}

// ── Transport-generic frame exchanges ────────────────────────────────────────
//
// Generic over `Read + Write` so the identical framing / push-routing logic
// runs over a real `UnixStream` and a test `socketpair`. Written generically so
// a future migration of the Windows client onto this shared path (under
// HW-verify) can lift these as-is; today only the Unix client consumes them.

/// Perform the `ContractNegotiate` handshake over `stream`: write the request,
/// read the response, interpret it (neutral). `Err` on transport failure.
fn negotiate_over<S: Read + Write>(stream: &mut S) -> Result<NegotiateParse, WireError> {
    let request = build_contract_negotiate(CLIENT_PROTOCOL_VERSION);
    write_frame(stream, &request)?;
    let response: Value = read_frame(stream)?;
    Ok(interpret_negotiate_response(&response))
}

/// Write one request envelope and read frames until the matching response
/// arrives, handing push frames (empty `request-id`) to `push`. `Err` means the
/// transport died and the caller should reconnect.
fn exchange<S: Read + Write>(
    stream: &mut S,
    envelope: &Value,
    request_id: &str,
    push: &dyn Fn(&Value),
) -> Result<RequestResponse, WireError> {
    write_frame(stream, envelope)?;
    loop {
        let frame: Value = read_frame(stream)?;
        let frame_request_id = frame
            .get("request-id")
            .or_else(|| frame.get("request_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if frame_request_id.is_empty() {
            // Server-initiated frame; the whole frame goes to the router so a
            // payload-less one is reported rather than vanishing here.
            push(&frame);
            continue;
        }
        if frame_request_id == request_id {
            return Ok(parse_response(&frame));
        }
        // Mismatched request_id on a single-in-flight socket — log and skip.
        eprintln!(
            "nrr-ipc-client(unix): discarding frame with unexpected request_id={frame_request_id}"
        );
    }
}

// ── Subscription survival across reconnects ──────────────────────────────────

/// Remember an accepted subscription request so it can be replayed on the next
/// connection. Only the subscribe operation is remembered; every other accepted
/// request is stateless from the connection's point of view.
fn remember_subscription(inner: &Arc<ClientInner>, envelope: &Value) {
    let is_subscribe = envelope
        .get("operation")
        .and_then(|v| v.as_str())
        .map(|op| op == IpcOperationName::StatusUpdatesSubscribe.slug())
        .unwrap_or(false);
    if !is_subscribe {
        return;
    }
    if let Ok(mut g) = inner.last_subscribe.lock() {
        *g = Some(envelope.clone());
    }
}

/// Re-issue the remembered subscription on a freshly connected socket. Runs
/// before the dispatch loop so events emitted right after reconnect are not
/// missed. Returns `false` when the transport died and the caller must
/// reconnect.
fn replay_subscription<S: Read + Write>(inner: &Arc<ClientInner>, stream: &mut S) -> bool {
    let remembered = match inner.last_subscribe.lock() {
        Ok(g) => g.clone(),
        Err(_) => {
            eprintln!("nrr-ipc-client(unix): resubscribe skipped — subscription lock poisoned");
            return true;
        }
    };
    let Some(mut replay) = remembered else {
        // Nobody ever subscribed on this client — nothing to restore.
        return true;
    };

    let seq = inner.replay_seq.fetch_add(1, Ordering::SeqCst);
    let request_id = format!("resubscribe-{seq}");
    match replay.as_object_mut() {
        Some(obj) => {
            obj.insert("request-id".into(), Value::String(request_id.clone()));
        }
        None => {
            eprintln!(
                "nrr-ipc-client(unix): resubscribe skipped — remembered envelope not an object"
            );
            return true;
        }
    }

    // Push frames queued ahead of the reply are routed, not discarded — that is
    // exactly what `exchange` already does for a caller request.
    let push = |frame: &Value| route_push_frame(inner, frame, "resubscribe");
    match exchange(stream, &replay, &request_id, &push) {
        Ok(RequestResponse::Ok(_)) => {
            eprintln!("nrr-ipc-client(unix): resubscribed after reconnect (id={request_id})");
            true
        }
        Ok(RequestResponse::ServerError { code, message, .. }) => {
            eprintln!("nrr-ipc-client(unix): resubscribe rejected by server: {code:?} {message}");
            true
        }
        Ok(RequestResponse::BadResponse(reason)) => {
            eprintln!("nrr-ipc-client(unix): resubscribe got a malformed reply: {reason}");
            true
        }
        Ok(RequestResponse::Disconnected) => false,
        Err(e) => {
            inner.set_status(ConnectionStatus::Disconnected {
                last_error: format!("resubscribe failed: {e}"),
            });
            eprintln!("nrr-ipc-client(unix): resubscribe transport failure: {e}");
            false
        }
    }
}

/// Hand a server-initiated frame to the subscriber. Every outcome is reported:
/// a silently dropped push is indistinguishable from one that never arrived,
/// and that ambiguity costs whole test runs to diagnose.
fn route_push_frame(inner: &Arc<ClientInner>, frame: &Value, source: &str) {
    let Some(payload) = frame.get("payload").cloned() else {
        eprintln!("nrr-ipc-client(unix): push frame without payload (source={source})");
        return;
    };
    let event_type = payload
        .get("event")
        .and_then(|e| e.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let Ok(guard) = inner.push_tx.lock() else {
        eprintln!("nrr-ipc-client(unix): push {event_type} lost — subscriber lock poisoned");
        return;
    };
    let Some(tx) = guard.as_ref() else {
        eprintln!("nrr-ipc-client(unix): push {event_type} discarded — nobody subscribed");
        return;
    };
    match tx.try_send(payload) {
        Ok(()) => eprintln!("nrr-ipc-client(unix): push {event_type} delivered (source={source})"),
        Err(e) => eprintln!("nrr-ipc-client(unix): push {event_type} dropped — channel full ({e})"),
    }
}

// ── Shutdown / backoff helpers ───────────────────────────────────────────────

fn wait_for_shutdown_or_force_reconnect(
    inner: &Arc<ClientInner>,
    request_rx: &Receiver<PendingRequest>,
) {
    while !inner.shutdown.load(Ordering::SeqCst) {
        if inner.force_reconnect.swap(false, Ordering::SeqCst) {
            break;
        }
        // Drain pending requests so callers don't hang while terminal.
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
        // Consume (swap), not just observe: see the matching comment in
        // `client.rs::sleep_observing_shutdown` — a `force_reconnect()` nudge
        // that fires during backoff must not survive past the wake-up it
        // causes, or the NEXT successful connect gets torn down by
        // `serve_requests`' own top-of-loop check before serving a request,
        // and the worker livelocks between "reconnect" and "instant
        // disconnect" for as long as callers keep nudging on failure.
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
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::AtomicU32;

    // ── Transport-generic helpers over a socketpair ──────────────────────────

    #[test]
    fn negotiate_over_socketpair_parses_ok() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        let server_thread = thread::spawn(move || {
            let req: Value = read_frame(&mut server).expect("server read");
            assert_eq!(req["operation"], "contract.negotiate");
            let resp = serde_json::json!({
                "ok": true,
                "payload": {
                    "server-version": 1,
                    "service-version": "test-1.0",
                    "session-id": "sess-1",
                }
            });
            write_frame(&mut server, &resp).expect("server write");
        });

        match negotiate_over(&mut client).expect("negotiate") {
            NegotiateParse::Ok(info) => {
                assert_eq!(info.server_protocol, 1);
                assert_eq!(info.service_version, "test-1.0");
            }
            _ => panic!("expected Ok"),
        }
        server_thread.join().expect("server thread");
    }

    #[test]
    fn exchange_socketpair_round_trips_and_routes_push() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        let server_thread = thread::spawn(move || {
            let req: Value = read_frame(&mut server).expect("server read");
            let rid = req["request-id"].as_str().unwrap_or("").to_string();
            // Emit an unsolicited push frame first (empty request-id), then the
            // real response — the client must route the push and match the reply.
            let push = serde_json::json!({ "request-id": "", "payload": { "evt": "hi" } });
            write_frame(&mut server, &push).expect("server push");
            let resp = serde_json::json!({ "ok": true, "request-id": rid, "payload": { "n": 5 } });
            write_frame(&mut server, &resp).expect("server resp");
        });

        let envelope = serde_json::json!({ "request-id": "req-7", "operation": "x" });
        let pushed = Arc::new(Mutex::new(Vec::<Value>::new()));
        let pushed_c = Arc::clone(&pushed);
        let sink = move |v: &Value| pushed_c.lock().expect("lock").push(v.clone());

        let resp = exchange(&mut client, &envelope, "req-7", &sink).expect("exchange");
        match resp {
            RequestResponse::Ok(p) => assert_eq!(p["n"], 5),
            _ => panic!("expected Ok"),
        }
        assert_eq!(pushed.lock().expect("lock").len(), 1);
        server_thread.join().expect("server thread");
    }

    // ── End-to-end client against a stub listener ────────────────────────────

    struct TempSock(PathBuf);
    impl Drop for TempSock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    fn temp_sock_path() -> TempSock {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-unix-client-test-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&p);
        TempSock(p)
    }

    /// Minimal service stand-in: accept connections until `stop` is set; per
    /// connection, answer `contract.negotiate` with an ok handshake and echo
    /// every other request back with its `request-id`. The listener is
    /// non-blocking so `accept` never wedges the thread — it polls `stop`
    /// between attempts, so `join()` always returns once the test sets `stop`
    /// (no dependency on a fixed connection count, which is what would deadlock
    /// when a reconnect races the accept loop).
    fn spawn_stub_server(listener: UnixListener, stop: Arc<AtomicBool>) -> thread::JoinHandle<()> {
        spawn_stub_server_counting(listener, stop, Arc::new(AtomicU32::new(0)))
    }

    /// Same stand-in, plus a counter of `status.updates.subscribe` requests
    /// seen across *all* connections, and one push frame emitted ahead of every
    /// subscribe reply — the frame ordering a replayed subscription has to
    /// survive (push queued before the response it is waiting for).
    fn spawn_stub_server_counting(
        listener: UnixListener,
        stop: Arc<AtomicBool>,
        subscribes: Arc<AtomicU32>,
    ) -> thread::JoinHandle<()> {
        let _ = listener.set_nonblocking(true);
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let mut conn = match listener.accept() {
                    Ok((c, _)) => {
                        let _ = c.set_nonblocking(false); // blocking per-conn I/O
                        c
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(_) => return,
                };
                // Serve this connection until the client drops it (read error).
                while let Ok(frame) = read_frame::<_, Value>(&mut conn) {
                    let op = frame
                        .get("operation")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let rid = frame
                        .get("request-id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    if op == IpcOperationName::StatusUpdatesSubscribe.slug() {
                        subscribes.fetch_add(1, Ordering::SeqCst);
                        let push = serde_json::json!({
                            "request-id": "",
                            "payload": { "event": { "type": "stub-status-update" } }
                        });
                        if write_frame(&mut conn, &push).is_err() {
                            break;
                        }
                    }
                    let resp = if op == "contract.negotiate" {
                        serde_json::json!({
                            "ok": true,
                            "request-id": rid,
                            "payload": {
                                "server-version": 1,
                                "service-version": "stub",
                                "session-id": "stub-session",
                            }
                        })
                    } else {
                        serde_json::json!({
                            "ok": true,
                            "request-id": rid,
                            "payload": { "echoed-op": op }
                        })
                    };
                    if write_frame(&mut conn, &resp).is_err() || stop.load(Ordering::SeqCst) {
                        break;
                    }
                }
            }
        })
    }

    /// Poll `predicate` until true or `timeout` elapses. Returns whether it
    /// became true (avoids sleeping on a fixed delay — no `Date::now` needed).
    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if predicate() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        predicate()
    }

    #[test]
    fn connects_and_handshakes_against_stub() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock.0).expect("bind");
        let stop = Arc::new(AtomicBool::new(false));
        let server = spawn_stub_server(listener, Arc::clone(&stop));

        let client = UnixIpcClient::start_at(sock.0.clone());
        assert!(
            wait_until(Duration::from_secs(3), || client
                .connection_status()
                .is_connected()),
            "client never reached Connected: {:?}",
            client.connection_status()
        );
        let info = client.negotiate_info().expect("negotiate info");
        assert_eq!(info.server_protocol, 1);
        assert_eq!(info.service_version, "stub");

        stop.store(true, Ordering::SeqCst);
        client.shutdown();
        drop(client);
        let _ = server.join();
    }

    #[test]
    fn round_trips_a_call_against_stub() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock.0).expect("bind");
        let stop = Arc::new(AtomicBool::new(false));
        let server = spawn_stub_server(listener, Arc::clone(&stop));

        let client = UnixIpcClient::start_at(sock.0.clone());
        assert!(wait_until(Duration::from_secs(3), || client
            .connection_status()
            .is_connected()));

        let resp = client
            .call(
                IpcOperationName::ServiceHealthGet,
                serde_json::json!({}),
                Duration::from_secs(2),
            )
            .expect("call ok");
        assert_eq!(resp["echoed-op"], "service.health.get");

        stop.store(true, Ordering::SeqCst);
        client.shutdown();
        drop(client);
        let _ = server.join();
    }

    #[test]
    fn reconnects_after_forced_reconnect() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock.0).expect("bind");
        let stop = Arc::new(AtomicBool::new(false));
        // Unbounded accept loop: the client reconnects onto a fresh connection,
        // and the server keeps accepting until `stop`.
        let server = spawn_stub_server(listener, Arc::clone(&stop));

        let client = UnixIpcClient::start_at(sock.0.clone());
        assert!(wait_until(Duration::from_secs(3), || client
            .connection_status()
            .is_connected()));
        // A call works on the first connection.
        assert!(client
            .call(
                IpcOperationName::ServiceHealthGet,
                serde_json::json!({}),
                Duration::from_secs(2),
            )
            .is_ok());

        // Force the worker to drop the connection and reconnect. Prove recovery
        // by polling `call()` until it succeeds again — this depends only on
        // the client actually re-establishing a working connection, not on
        // status-flag or connection-count timing (which is what deadlocked the
        // earlier count-based version).
        client.force_reconnect();
        let recovered = wait_until(Duration::from_secs(5), || {
            client
                .call(
                    IpcOperationName::ServiceHealthGet,
                    serde_json::json!({}),
                    Duration::from_millis(500),
                )
                .is_ok()
        });
        assert!(recovered, "client did not recover after forced reconnect");

        stop.store(true, Ordering::SeqCst);
        client.shutdown();
        drop(client);
        let _ = server.join();
    }

    // A subscription is a property of the connection: after a reconnect the
    // server knows nothing about the subscriber, and a caller that subscribed
    // once and went quiet (the tray does exactly that) would never see another
    // event for the rest of its life. The client owns reconnect, so the client
    // must re-issue the subscription — without any caller involvement, which is
    // what this test asserts by never calling `subscribe` a second time.
    #[test]
    fn resubscribes_after_reconnect_without_caller_help() {
        let sock = temp_sock_path();
        let listener = UnixListener::bind(&sock.0).expect("bind");
        let stop = Arc::new(AtomicBool::new(false));
        let subscribes = Arc::new(AtomicU32::new(0));
        let server =
            spawn_stub_server_counting(listener, Arc::clone(&stop), Arc::clone(&subscribes));

        let client = UnixIpcClient::start_at(sock.0.clone());
        assert!(wait_until(Duration::from_secs(3), || client
            .connection_status()
            .is_connected()));

        let pushes = client.subscribe_push();
        client
            .call(
                IpcOperationName::StatusUpdatesSubscribe,
                serde_json::json!({}),
                Duration::from_secs(2),
            )
            .expect("subscribe accepted");
        assert_eq!(subscribes.load(Ordering::SeqCst), 1);
        assert!(
            pushes.recv_timeout(Duration::from_secs(2)).is_ok(),
            "push on the first connection never reached the subscriber"
        );

        // Drop the connection the way a service restart does.
        client.force_reconnect();

        assert!(
            wait_until(Duration::from_secs(5), || subscribes.load(Ordering::SeqCst)
                >= 2),
            "client never replayed the subscription after reconnect"
        );
        assert!(
            pushes.recv_timeout(Duration::from_secs(2)).is_ok(),
            "push after the replayed subscription never reached the subscriber"
        );

        stop.store(true, Ordering::SeqCst);
        client.shutdown();
        drop(client);
        let _ = server.join();
    }

    // Nothing to replay must stay a no-op: a client that never subscribed keeps
    // reconnecting normally instead of writing a bogus frame on every connect.
    #[test]
    fn replay_is_a_no_op_without_a_remembered_subscription() {
        let (mut client, mut server) = UnixStream::pair().expect("socketpair");
        let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent")));
        assert!(replay_subscription(&inner, &mut client));
        // Nothing was written, so the peer sees an empty (would-block) socket.
        server
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("read timeout");
        let mut buf = [0u8; 1];
        assert!(server.read(&mut buf).is_err(), "replay wrote a frame");
    }

    #[test]
    fn call_returns_disconnected_before_connected() {
        // Point at a path with no listener → never connects. Immediate call
        // returns Disconnected rather than hanging.
        let sock = temp_sock_path(); // nothing bound here
        let client = UnixIpcClient::start_at(sock.0.clone());
        let result = client.call(
            IpcOperationName::ServiceHealthGet,
            serde_json::json!({}),
            Duration::from_millis(50),
        );
        assert!(matches!(result, Err(IpcClientError::Disconnected)));
        client.shutdown();
    }

    #[test]
    fn shutdown_is_idempotent() {
        let sock = temp_sock_path();
        let client = UnixIpcClient::start_at(sock.0.clone());
        client.shutdown();
        client.shutdown(); // no panic
    }

    // Regression (mirrors the equivalent test in `client.rs` for the Windows
    // client): a `force_reconnect()` nudge fired while the worker is backing
    // off must not survive the early wake-up it causes, or the next
    // successful `serve_requests()` tears itself down before serving a
    // request, because its own top-of-loop check would still see the flag
    // `true`.
    #[test]
    fn sleep_observing_shutdown_consumes_force_reconnect_flag() {
        let inner = Arc::new(ClientInner::new(PathBuf::from("/nonexistent")));
        inner.force_reconnect.store(true, Ordering::SeqCst);

        let started = Instant::now();
        sleep_observing_shutdown(&inner, Duration::from_secs(10));

        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!inner.force_reconnect.load(Ordering::SeqCst));
    }
}
