//! Windows named-pipe IPC server.
//!
//! ## Architecture
//!
//! The server binds `\\.\pipe\NetRuleRouter\service-v1` with the canonical
//! DACL from `named_pipe_acl` (LocalSystem + Builtin Administrators full,
//! Authenticated Users RW with low-IL no-write-up).
//!
//! Each accepted connection is handled by a **dedicated worker thread**
//! (per-connection thread, not a thread pool). Hard cap: 32 concurrent
//! connections.
//!
//! ### Tick-model accept loop
//!
//! `WindowsNamedPipeServer::bind()` returns a `WindowsNamedPipeAcceptor`
//! that exposes a single-tick accept primitive
//! consumable by `ServiceSupervisor`:
//!
//! ```text
//! let server = WindowsNamedPipeServer::new(router, audit);
//! let acceptor = server.bind()?;
//! loop {
//!     match acceptor.accept_one() {
//!         AcceptOutcome::Connected | AcceptOutcome::Idle => continue,
//!         AcceptOutcome::ShutdownRequested => break,
//!         AcceptOutcome::Err(e) => /* policy decides: rebind or retire */,
//!     }
//! }
//! acceptor.request_shutdown();
//! acceptor.join_workers();
//! ```
//!
//! Wire format (4-byte BE u32 length + UTF-8 JSON, `IPC_MAX_MESSAGE_BYTES`),
//! DACL, identity whitelist, and busy-close at MAX_CONCURRENT_CONNECTIONS
//! match `nrr-ipc-client`'s protocol bit-for-bit.
//!
//! Request flow per connection (handled inside the worker thread):
//! 1. Identify caller via `named_pipe_identity::classify_pipe_client`
//! 2. On reject → audit log + close handle
//! 3. Loop: `read_frame` → `IpcRouter::dispatch` → `write_frame`
//! 4. Exit on EOF, transport error, or worker-shutdown signal
//!
//! ## Pipe instance lifecycle
//!
//! Each `accept_one` tick creates one new pipe instance via
//! `CreateNamedPipeW`, then blocks on `ConnectNamedPipe`. When a client
//! connects, the instance is handed off to a worker thread; the next
//! `accept_one` call creates a fresh instance for the next client. Total
//! active instances = (1 accepting per concurrent supervisor tick) +
//! (N workers, ≤ 32). When the cap is hit, the new connection is
//! busy-closed and the tick returns `Idle` so the supervisor keeps
//! ticking without charging the policy retry budget.
//!
//! ## Shutdown
//!
//! `request_shutdown()` sets the shutdown flag and wakes any pending
//! `ConnectNamedPipe` by self-connecting to the pipe via `CreateFileW`.
//! After waking, the accept tick re-checks the flag and returns
//! `ShutdownRequested` instead of handing the (self) connection off.
//! Workers observe the same shutdown flag (`worker_shutdown`) and break
//! out of their dispatch loop on the next iteration.
//!
//! ## Testability
//!
//! The Windows-specific transport (`#[cfg(target_os = "windows")]`) is the
//! production path. For cross-platform unit tests we use
//! `InMemoryNamedPipeTransport` which implements the same accept / read /
//! write contract over `mpsc` channels. See `named_pipe_inmem.rs`.
//! Real-pipe smoke tests are in `tests/named_pipe_server_smoke.rs`.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_NONE, OPEN_EXISTING};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use nrr_service_runtime::ipc_push::{
    extract_subscription_id, flush_push_frames, PUSH_BATCH_SIZE, PUSH_POLL_INTERVAL,
};
use nrr_service_runtime::{
    AcceptError, AcceptErrorCategory, AcceptOutcome, ActiveSidRegistry, EventBus, IpcAcceptor,
    IpcAuditEmitter, IpcBindError, IpcError, IpcErrorCode, IpcRequestContext, IpcRequestEnvelope,
    IpcResponseEnvelope, IpcRouter, IpcServer,
};

use crate::named_pipe_acl::PipeSecurityAttributes;
use crate::named_pipe_identity::{classify_pipe_client, ClientRejectReason};
use nrr_shared::ipc_wire::{read_frame, write_frame, WireError};

/// Canonical pipe path. Derived from the cross-OS endpoint SSOT in
/// `nrr-shared::ipc_transport` (block 19.2) so the server and the client
/// (`nrr-ipc-client`) can never drift. This module is `#[cfg(windows)]`, so
/// the SSOT resolves to the named-pipe address here. The versioned `-v1`
/// suffix lets us migrate the protocol without breaking running clients.
pub const PIPE_NAME: &str = nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;

/// Hard limit on concurrent connections. 32 covers GUI + Tray + a few
/// dev tools comfortably; beyond that the server starts rejecting.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Pipe in/out buffer size (bytes). Smaller than max message because
/// `PIPE_TYPE_MESSAGE` will fragment on the wire as needed.
const PIPE_BUFFER_SIZE: u32 = 64 * 1024;

/// How long a freshly connected client may stay silent before the slot is
/// taken back. Generous — a GUI starting on a cold machine is slower than one
/// might think — but finite, which is the whole point. Mirrors the AF_UNIX
/// server's window; the two transports must not disagree on how patient the
/// service is.
const FIRST_FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// How long one push frame may take to reach a subscriber. A client that
/// stopped reading must not park the worker thread that serves it: past this
/// window the subscription is dropped and the connection slot freed.
const PUSH_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// `HANDLE` newtype that is `Send` so we can move pipe handles into
/// worker threads. The underlying handle is exclusively owned by one
/// thread at a time (acceptor hands it off when it spawns the worker;
/// the worker is the sole owner thereafter).
struct SendableHandle(HANDLE);

// SAFETY: HANDLE wraps a *mut c_void. We never share a handle between
// threads concurrently — the accept tick relinquishes ownership when
// it spawns the worker; the worker is the sole owner thereafter.
unsafe impl Send for SendableHandle {}

/// Production named-pipe IPC server. Holds router + audit references,
/// constructs an acceptor on demand via `bind()`. Cheap to construct —
/// real Win32 work happens in `bind()` and per-tick in `accept_one()`.
pub struct WindowsNamedPipeServer {
    router: Arc<IpcRouter>,
    audit: Arc<dyn IpcAuditEmitter>,
    /// Tracks per-SID active connections. Worker threads call `on_connect`
    /// after identity classification and `on_disconnect` before the pipe
    /// closes. `None` for transports that don't need the registry.
    active_sids: Option<Arc<ActiveSidRegistry>>,
    /// Shared `EventBus` so per-connection worker threads can poll pending
    /// push events for the connection's subscription (if any) and write
    /// push frames on the same pipe. `None` disables push delivery.
    event_bus: Option<Arc<EventBus>>,
}

impl WindowsNamedPipeServer {
    /// Construct a server without the per-SID active-connection registry.
    /// The live runtime always wires the registry via
    /// [`Self::new_with_active_sid_registry`]; this registry-less
    /// constructor only survives for unit tests that don't exercise SID
    /// accounting.
    #[cfg(test)]
    pub fn new(router: Arc<IpcRouter>, audit: Arc<dyn IpcAuditEmitter>) -> Self {
        Self {
            router,
            audit,
            active_sids: None,
            event_bus: None,
        }
    }

    /// Attach the shared `EventBus` so worker threads can flush push
    /// frames after a `StatusUpdatesSubscribe` request.
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Construct a server that updates `active_sids` for every connection,
    /// so the per-SID apply orchestrator and route coordinator see
    /// membership transitions — a tray connection marks its SID
    /// routing-active, which is what lets enforcement target the user.
    pub fn new_with_active_sid_registry(
        router: Arc<IpcRouter>,
        audit: Arc<dyn IpcAuditEmitter>,
        active_sids: Arc<ActiveSidRegistry>,
    ) -> Self {
        Self {
            router,
            audit,
            active_sids: Some(active_sids),
            event_bus: None,
        }
    }
}

impl IpcServer for WindowsNamedPipeServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        let security = PipeSecurityAttributes::for_pipe()
            .map_err(|e| IpcBindError::SecurityDescriptor(e.to_string()))?;
        Ok(Box::new(WindowsNamedPipeAcceptor {
            router: Arc::clone(&self.router),
            audit: Arc::clone(&self.audit),
            security: Arc::new(security),
            active_sids: self.active_sids.clone(),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            worker_shutdown: Arc::new(AtomicBool::new(false)),
            active_count: Arc::new(AtomicUsize::new(0)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
            event_bus: self.event_bus.clone(),
        }))
    }
}

/// Windows-specific acceptor produced by `WindowsNamedPipeServer::bind`.
///
/// Holds the security descriptor (built once per `bind` so SDDL parse
/// errors surface during bind, not on every tick) and the shared shutdown
/// state. `Send + Sync` — the supervisor moves it into a dedicated thread
/// to call `accept_one`, but `request_shutdown` may be called from the
/// supervisor's main thread.
pub struct WindowsNamedPipeAcceptor {
    router: Arc<IpcRouter>,
    audit: Arc<dyn IpcAuditEmitter>,
    /// Owned security descriptor. Wrapped in `Arc` so it survives if the
    /// acceptor is moved across threads. `PipeSecurityAttributes` is
    /// `Send + Sync` (see `named_pipe_acl.rs`).
    security: Arc<PipeSecurityAttributes>,
    /// Per-SID active-connection registry. Workers notify it of connect /
    /// disconnect so the per-user routing orchestrator sees membership
    /// changes.
    active_sids: Option<Arc<ActiveSidRegistry>>,
    /// Set by `request_shutdown`. Checked at the start of `accept_one`
    /// and again after `ConnectNamedPipe` wakes (whether by real client
    /// or self-connect wake from `request_shutdown`).
    shutdown_requested: Arc<AtomicBool>,
    /// Propagates to per-connection worker threads via the `shutdown`
    /// argument of `handle_connection`. Workers break out of their
    /// dispatch loop on the next observation.
    worker_shutdown: Arc<AtomicBool>,
    /// Concurrent connection count. Accept ticks busy-close inbound
    /// connections when the count is at `MAX_CONCURRENT_CONNECTIONS`.
    active_count: Arc<AtomicUsize>,
    /// Worker handles for `join_workers`. Periodically pruned of
    /// finished entries so the vec does not grow unboundedly.
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
    /// Shared `EventBus`. Per-connection workers use it to flush push
    /// frames after their `StatusUpdatesSubscribe` request.
    event_bus: Option<Arc<EventBus>>,
}

impl IpcAcceptor for WindowsNamedPipeAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        if self.shutdown_requested.load(Ordering::SeqCst) {
            return AcceptOutcome::ShutdownRequested;
        }
        tracing::trace!(
            target: "nrr::ipc",
            active_count = self.active_count.load(Ordering::SeqCst),
            "accept tick"
        );

        let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        // Create a pending pipe instance with FILE_FLAG_OVERLAPPED. The
        // handle_connection worker uses TWO threads on the same pipe
        // handle (reader sub-thread for ReadFile + main thread for
        // WriteFile responses + push frames). On a synchronous handle
        // Windows serialises all I/O on a single kernel I/O lock —
        // ReadFile (waiting for next request) would block WriteFile
        // (sending response to current request), and the connection
        // would deadlock after the first round-trip. With
        // FILE_FLAG_OVERLAPPED each I/O takes its own OVERLAPPED + event
        // and the kernel does not serialise. See `PipeIo::read` / `write`
        // below for the overlapped wait pattern.
        //
        // SAFETY: pipe_name_wide is null-terminated UTF-16; security pointer
        // is valid for the duration of CreateNamedPipeW (held by Arc<self>).
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name_wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                Some(self.security.as_ptr()),
            )
        };
        if pipe.is_invalid() {
            // SAFETY: GetLastError is thread-local; safe to read.
            let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
            return AcceptOutcome::Err(AcceptError {
                category: AcceptErrorCategory::PipeCreate,
                message: format!("CreateNamedPipeW failed: 0x{code:08X}"),
            });
        }

        tracing::trace!(target: "nrr::ipc", "pipe instance created, awaiting connect");
        // Overlapped ConnectNamedPipe: create a transient event, pass it
        // via OVERLAPPED. If the call returns ERROR_IO_PENDING the wait
        // is performed via GetOverlappedResult; ERROR_PIPE_CONNECTED means
        // the client raced ahead and is already attached. The event handle
        // is closed before we move on.
        //
        // SAFETY: pipe is a valid overlapped pipe handle; overlapped struct
        // lives on this stack frame until the wait completes; event handle
        // is owned and closed below.
        let connect_event = unsafe { CreateEventW(None, false, false, PCWSTR::null()) };
        let connect_event = match connect_event {
            Ok(h) if !h.is_invalid() => h,
            _ => {
                let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                return AcceptOutcome::Err(AcceptError {
                    category: AcceptErrorCategory::PipeCreate,
                    message: format!("CreateEventW failed: 0x{code:08X}"),
                });
            }
        };
        let mut overlapped: OVERLAPPED = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = connect_event;
        let connect_result = unsafe { ConnectNamedPipe(pipe, Some(&mut overlapped)) };
        let connected = match connect_result {
            Ok(()) => true,
            Err(e) => {
                let code = e.code().0 as u32;
                if code == 535 {
                    // ERROR_PIPE_CONNECTED — client already attached.
                    true
                } else if code == 0x800703E5 || code == 997 {
                    // ERROR_IO_PENDING (997 / 0x800703E5 HRESULT form) —
                    // wait for completion via GetOverlappedResult.
                    let mut transferred: u32 = 0;
                    match unsafe { GetOverlappedResult(pipe, &overlapped, &mut transferred, true) }
                    {
                        Ok(()) => true,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
        };
        unsafe {
            let _ = CloseHandle(connect_event);
        }
        tracing::trace!(target: "nrr::ipc", connected, "connect completed");

        // Re-check shutdown — if request_shutdown ran during ConnectNamedPipe,
        // the wake came from our own self-connect, not a real client.
        if self.shutdown_requested.load(Ordering::SeqCst) {
            // SAFETY: pipe is the handle we created above.
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            return AcceptOutcome::ShutdownRequested;
        }

        if !connected {
            // SAFETY: pipe is valid; we close on transient error path. The
            // supervisor will tick again without charging policy budget.
            unsafe {
                let _ = CloseHandle(pipe);
            }
            return AcceptOutcome::Idle;
        }

        // Throttle: busy-close if at cap. Idle outcome — the supervisor keeps
        // ticking; this is normal load shedding, not policy failure.
        if self.active_count.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
            send_busy_close(pipe);
            return AcceptOutcome::Idle;
        }

        tracing::debug!(target: "nrr::ipc", "client connected, spawning worker");
        // Hand off to a per-connection worker thread.
        let router_clone = Arc::clone(&self.router);
        let audit_clone = Arc::clone(&self.audit);
        let active_clone = Arc::clone(&self.active_count);
        let worker_shutdown_clone = Arc::clone(&self.worker_shutdown);
        let registry_clone = self.active_sids.clone();
        let event_bus_clone = self.event_bus.clone();
        // The slot is a GUARD, not a pair of counter writes: a panic in
        // dispatch unwinds past a trailing `fetch_sub` and leaks the slot, and
        // thirty-two of those close the transport for good.
        let slot = nrr_service_runtime::connection_slot::ConnectionSlot::claim(active_clone);
        let pipe_send = SendableHandle(pipe);
        let spawn_result = thread::Builder::new()
            .name("nrr-ipc-worker".into())
            .spawn(move || {
                let _slot = slot;
                handle_connection(
                    pipe_send,
                    router_clone,
                    audit_clone,
                    worker_shutdown_clone,
                    registry_clone,
                    event_bus_clone,
                );
            });

        match spawn_result {
            Ok(handle) => {
                if let Ok(mut guard) = self.worker_handles.lock() {
                    // Opportunistically prune finished workers.
                    guard.retain(|j| !j.is_finished());
                    guard.push(handle);
                }
                AcceptOutcome::Connected
            }
            Err(e) => {
                // The guard was moved into the closure that failed to spawn, so
                // it has already released the slot.
                send_busy_close(pipe);
                AcceptOutcome::Err(AcceptError {
                    category: AcceptErrorCategory::WorkerSpawn,
                    message: format!("worker thread spawn failed: {e}"),
                })
            }
        }
    }

    fn request_shutdown(&self) {
        // Order matters: flip flags first so any thread that wakes immediately
        // after our self-connect sees them and exits.
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.worker_shutdown.store(true, Ordering::SeqCst);

        // Wake any pending ConnectNamedPipe by self-connecting to the pipe.
        // Best-effort: if the pipe was never created (no accept_one ran yet)
        // CreateFileW returns an error, which is fine — the flag check at
        // the start of the next accept_one will short-circuit.
        let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: pipe_name_wide is null-terminated UTF-16; we open with
        // standard read/write access and immediately close the handle.
        unsafe {
            if let Ok(client) = CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            ) {
                let _ = CloseHandle(client);
            }
        }
    }

    fn join_workers(&self) {
        if let Ok(mut guard) = self.worker_handles.lock() {
            let handles = std::mem::take(&mut *guard);
            for h in handles {
                let _ = h.join();
            }
        }
    }

    fn active_connections(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }
}

impl Drop for WindowsNamedPipeAcceptor {
    fn drop(&mut self) {
        // Best-effort: signal shutdown so any pending accept_one tick exits.
        // Workers are NOT joined here — supervisor owns drain ordering and
        // must call join_workers() explicitly.
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.worker_shutdown.store(true, Ordering::SeqCst);
        // Best-effort wake. Same logic as request_shutdown, but inlined to
        // avoid taking &self through a trait method call inside drop.
        let pipe_name_wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: see request_shutdown.
        unsafe {
            if let Ok(client) = CreateFileW(
                PCWSTR(pipe_name_wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                HANDLE::default(),
            ) {
                let _ = CloseHandle(client);
            }
        }
    }
}

/// Send a busy-close on a pipe instance and shut it down. Used when
/// concurrency cap is hit before identity check.
fn send_busy_close(pipe: HANDLE) {
    // Best-effort: no router involvement here, just a synthetic
    // response to communicate the rejection to a client that opened
    // the pipe expecting normal protocol.
    let _ = write_busy_response(pipe);
    // SAFETY: pipe is a valid handle we own.
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
}

fn write_busy_response(pipe: HANDLE) -> Result<(), WireError> {
    let mut writer = PipeIo::new(pipe).map_err(WireError::Io)?;
    writer.set_timeout(Some(PUSH_WRITE_TIMEOUT));
    let env = IpcResponseEnvelope {
        request_id: String::new(),
        correlation_id: String::new(),
        operation_id: None,
        ok: false,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: None,
        error: Some(IpcError {
            code: IpcErrorCode::Internal,
            message: "service is busy; max concurrent connections reached".into(),
            diagnostics_id: None,
        }),
    };
    write_frame(&mut writer, &env)
}

/// Worker per-connection loop. Identical to the original 16.1
/// implementation — wire format, identity check, and dispatch contract
/// are unchanged.
fn handle_connection(
    pipe: SendableHandle,
    router: Arc<IpcRouter>,
    audit: Arc<dyn IpcAuditEmitter>,
    shutdown: Arc<AtomicBool>,
    active_sids: Option<Arc<ActiveSidRegistry>>,
    event_bus: Option<Arc<EventBus>>,
) {
    let pipe = pipe.0;
    let _ = audit; // audit hooks fire inside IpcRouter::dispatch via the
                   // router's own audit emitter; the per-connection one
                   // is reserved for transport-level auth events when 16.3
                   // wires them.

    // Step 1: identity check. On reject, write a Forbidden response and close.
    let identity = match classify_pipe_client(pipe) {
        Ok(id) => {
            tracing::debug!(
                target: "nrr::ipc",
                profile = ?id.profile,
                elevated = id.caller_is_elevated,
                pid = id.process_id,
                "client accepted"
            );
            id
        }
        Err(reason) => {
            tracing::warn!(target: "nrr::ipc", ?reason, "client rejected");
            let _ = write_reject_response(pipe, &reason);
            close_pipe(pipe);
            return;
        }
    };

    // Register this connection with the per-SID registry. RAII guard
    // pattern so on_disconnect always runs, including on early `break`
    // from the dispatch loop.
    let _registry_guard = active_sids.as_ref().map(|reg| {
        ActiveSidConnectionGuard::new(Arc::clone(reg), &identity.caller_sid, identity.profile)
    });

    // Reader sub-thread: the main loop needs to interleave request reads
    // with periodic EventBus polls, which isn't feasible with blocking
    // ReadFile on a synchronous pipe handle. A dedicated reader thread
    // does blocking reads and forwards each frame via mpsc; the main loop
    // uses recv_timeout to alternate between dispatching requests and
    // flushing push frames.
    let reader_pipe = SendableHandle(pipe);
    let (reader_tx, reader_rx) = std::sync::mpsc::sync_channel::<ReaderMsg>(8);
    // Helper fn boundary defeats Rust 2021 disjoint capture, which would
    // otherwise capture only the inner `HANDLE` field of `SendableHandle`
    // and bypass the `unsafe impl Send` on the wrapper.
    let reader_handle = thread::Builder::new()
        .name("nrr-ipc-reader".into())
        .spawn(move || run_reader_loop(reader_pipe, reader_tx))
        .ok();

    let mut writer = match PipeIo::new(pipe) {
        Ok(mut w) => {
            // Bound every write to this client, responses as well as push
            // frames. A peer that stopped reading is indistinguishable from a
            // slow one until the window expires, and an unbounded write parks
            // the worker thread — with it, one of the 32 connection slots — for
            // as long as that peer cares to sulk. Past the window the write
            // fails, the loop breaks, and teardown drops the subscription.
            w.set_timeout(Some(PUSH_WRITE_TIMEOUT));
            w
        }
        Err(e) => {
            tracing::warn!(target: "nrr::ipc", error = %e, "writer setup failed, dropping connection");
            close_pipe(pipe);
            return;
        }
    };
    let mut subscription_id: Option<String> = None;

    // Step 2: serve frames until error or shutdown.
    while !shutdown.load(Ordering::SeqCst) {
        match reader_rx.recv_timeout(PUSH_POLL_INTERVAL) {
            Ok(ReaderMsg::Request(request)) => {
                tracing::trace!(
                    target: "nrr::ipc",
                    op = request.operation.slug(),
                    request_id = %request.request_id,
                    "request received"
                );
                let ctx = IpcRequestContext {
                    client_profile: identity.profile,
                    caller_is_elevated: identity.caller_is_elevated,
                    caller_principal: nrr_service_runtime::UserPrincipal::from_windows_sid(
                        &identity.caller_sid,
                    )
                    .ok(),
                    // The caller elevates itself here (the broker), so the
                    // service never has to ask an authority about it.
                    caller_pid: None,
                };

                let response = router.dispatch(request, ctx);
                tracing::trace!(
                    target: "nrr::ipc",
                    ok = response.ok,
                    has_error = response.error.is_some(),
                    "request dispatched"
                );

                // The push pump only flushes once this connection has
                // subscribed; the handler returns the id in its payload.
                if subscription_id.is_none() && response.ok {
                    subscription_id = extract_subscription_id(&response);
                    if let Some(sub_id) = subscription_id.as_deref() {
                        tracing::info!(
                            target: "nrr::ipc-push",
                            subscription_id = sub_id,
                            profile = ?identity.profile,
                            subscribers = event_bus.as_ref().map(|b| b.subscriber_count()).unwrap_or(0),
                            bus_wired = event_bus.is_some(),
                            "push subscription opened"
                        );
                    }
                }

                if let Err(e) = write_frame(&mut writer, &response) {
                    tracing::warn!(target: "nrr::ipc", error = %e, "response write failed, closing connection");
                    break;
                }
            }
            Ok(ReaderMsg::Malformed) => {
                let _ = write_frame(
                    &mut writer,
                    &IpcResponseEnvelope {
                        request_id: String::new(),
                        correlation_id: String::new(),
                        operation_id: None,
                        ok: false,
                        stale: false,
                        diagnostics_id: None,
                        user_action_required: false,
                        payload: None,
                        error: Some(IpcError {
                            code: IpcErrorCode::MalformedRequest,
                            message: "frame decode failed".into(),
                            diagnostics_id: None,
                        }),
                    },
                );
                break;
            }
            Ok(ReaderMsg::Closed) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // Push pump tick. Only flushes when this connection
                // has subscribed AND the bus is wired.
                if let (Some(sub_id), Some(bus)) = (subscription_id.as_ref(), event_bus.as_ref()) {
                    let failed = flush_push_frames(bus, sub_id, PUSH_BATCH_SIZE, |env| {
                        write_frame(&mut writer, env).map_err(|e| e.to_string())
                    });
                    if failed {
                        break;
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Drop subscription so EventBus stops accumulating events for it.
    if let (Some(sub_id), Some(bus)) = (subscription_id.as_ref(), event_bus.as_ref()) {
        bus.unsubscribe(sub_id);
        tracing::info!(
            target: "nrr::ipc-push",
            subscription_id = %sub_id,
            subscribers = bus.subscriber_count(),
            "push subscription closed"
        );
    }

    // Disconnect, cancel, JOIN, and only then close.
    //
    // The reader may be parked in an overlapped `ReadFile` on this handle.
    // Closing it underneath and walking away leaves that thread reading a handle
    // VALUE the next `CreateNamedPipeW` is free to reuse — a live reader on
    // someone else's kernel object. So the reader has to be joined; the ordering
    // is what makes that join finite.
    //
    // `DisconnectNamedPipe` comes FIRST because `CancelIoEx` alone only kills
    // what is pending RIGHT NOW: the reader could submit a fresh read in the
    // window between the cancel and the join, and that read — past the
    // first-frame window, so unbounded — would never return. A disconnected
    // instance fails a read immediately instead of parking it, which closes the
    // window. `CancelIoEx` then releases whatever was already in flight.
    //
    // SAFETY: `pipe` is still open and owned here — that is precisely why the
    // close comes last, after the only other thread that touches it has exited.
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CancelIoEx(pipe, None);
    }
    if let Some(reader) = reader_handle {
        let _ = reader.join();
    }
    // SAFETY: the reader has exited, so nothing else holds this handle.
    unsafe {
        let _ = CloseHandle(pipe);
    }
    // _registry_guard drops here → on_disconnect.
}

/// Message types from the reader sub-thread to the main connection loop.
/// Bounded mpsc keeps the reader from racing too far ahead of the
/// dispatcher.
enum ReaderMsg {
    Request(IpcRequestEnvelope),
    Malformed,
    Closed,
}

/// Body of the per-connection reader thread. Lives behind a fn boundary
/// so Rust 2021's disjoint capture analysis does not flag the closure as
/// `!Send` when it accesses the `HANDLE` field of `SendableHandle`.
fn run_reader_loop(pipe: SendableHandle, reader_tx: std::sync::mpsc::SyncSender<ReaderMsg>) {
    let mut io = match PipeIo::new(pipe.0) {
        Ok(io) => io,
        Err(e) => {
            tracing::warn!(target: "nrr::ipc", error = %e, "reader setup failed, closing connection");
            let _ = reader_tx.send(ReaderMsg::Closed);
            return;
        }
    };
    // Idle window for the FIRST frame only. A connection that says nothing holds
    // one of 32 slots for as long as it likes, and 32 silent connections make
    // the service unreachable without a single malformed byte. After the first
    // frame the window comes off: a subscriber legitimately sits quiet for hours
    // waiting to be pushed to, and cutting it would break the very thing the
    // connection is for.
    io.set_timeout(Some(FIRST_FRAME_IDLE_TIMEOUT));
    let mut first = true;
    loop {
        let msg = match read_frame::<_, IpcRequestEnvelope>(&mut io) {
            Ok(req) => ReaderMsg::Request(req),
            Err(e) if e.is_transport_dead() => ReaderMsg::Closed,
            // Nothing arrived in the window — a read that timed out reaches us
            // as a broken frame. Treat it as a client that never introduced
            // itself and give the slot back, rather than as a protocol offence.
            Err(_) if first => ReaderMsg::Closed,
            Err(_) => ReaderMsg::Malformed,
        };
        if first {
            first = false;
            io.set_timeout(None);
        }
        let terminal = !matches!(msg, ReaderMsg::Request(_));
        if reader_tx.send(msg).is_err() || terminal {
            break;
        }
    }
}

/// RAII guard that calls `ActiveSidRegistry::on_connect` on construction
/// and `on_disconnect` on drop, keeping connection accounting balanced
/// even when the dispatch loop exits via `break` from a malformed frame,
/// EOF, or supervisor shutdown.
struct ActiveSidConnectionGuard {
    registry: Arc<ActiveSidRegistry>,
    sid: String,
    profile: nrr_shared::ipc::IpcClientProfile,
}

impl ActiveSidConnectionGuard {
    fn new(
        registry: Arc<ActiveSidRegistry>,
        sid: &str,
        profile: nrr_shared::ipc::IpcClientProfile,
    ) -> Self {
        registry.on_connect(sid, profile);
        Self {
            registry,
            sid: sid.to_string(),
            profile,
        }
    }
}

impl Drop for ActiveSidConnectionGuard {
    fn drop(&mut self) {
        self.registry.on_disconnect(&self.sid, self.profile);
    }
}

fn write_reject_response(pipe: HANDLE, reason: &ClientRejectReason) -> Result<(), WireError> {
    let mut io = PipeIo::new(pipe).map_err(WireError::Io)?;
    io.set_timeout(Some(PUSH_WRITE_TIMEOUT));
    let env = IpcResponseEnvelope {
        request_id: String::new(),
        correlation_id: String::new(),
        operation_id: None,
        ok: false,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: None,
        error: Some(IpcError {
            code: IpcErrorCode::Forbidden,
            message: format!("client rejected: {reason}"),
            diagnostics_id: None,
        }),
    };
    write_frame(&mut io, &env)
}

fn close_pipe(pipe: HANDLE) {
    // SAFETY: pipe is a valid handle owned by the worker.
    unsafe {
        let _ = DisconnectNamedPipe(pipe);
        let _ = CloseHandle(pipe);
    }
}

/// `Read`/`Write` adapter for an overlapped Windows pipe handle.
///
/// The pipe is created with `FILE_FLAG_OVERLAPPED` so that the reader
/// sub-thread and the main worker thread can perform ReadFile / WriteFile
/// concurrently without kernel I/O lock
/// serialisation. Each PipeIo owns its own auto-reset event used as
/// the `OVERLAPPED.hEvent` for every call; the event is closed on drop.
struct PipeIo {
    pipe: HANDLE,
    event: HANDLE,
    /// Deadline for a single I/O. `None` waits as long as it takes — correct for
    /// a subscriber that legitimately sits quiet for hours, wrong for a client
    /// that has stopped reading.
    timeout: Option<Duration>,
}

impl PipeIo {
    fn new(pipe: HANDLE) -> std::io::Result<Self> {
        // SAFETY: bManualReset=false, bInitialState=false — auto-reset
        // event that starts unsignaled. Owned by this PipeIo and closed
        // on drop.
        let event = unsafe { CreateEventW(None, false, false, PCWSTR::null()) }
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        if event.is_invalid() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            pipe,
            event,
            timeout: None,
        })
    }

    fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    /// Wait for the pending operation to finish, giving up after `self.timeout`.
    ///
    /// A named pipe has no `set_read_timeout`, so the window is enforced by
    /// waiting on the operation's own event and cancelling what has not
    /// completed. The reap after `CancelIoEx` is NOT optional and NOT a
    /// courtesy: until the kernel reports the operation finished it may still
    /// write into `overlapped` and the caller's buffer, both of which live on a
    /// stack frame that is about to go away.
    fn await_overlapped(
        &self,
        overlapped: &mut OVERLAPPED,
        transferred: &mut u32,
    ) -> std::io::Result<()> {
        let Some(timeout) = self.timeout else {
            // SAFETY: the operation is pending on `overlapped`, which outlives
            // this call; blocking here is what keeps that true.
            return unsafe { GetOverlappedResult(self.pipe, overlapped, transferred, true) }
                .map_err(|e| std::io::Error::from_raw_os_error(e.code().0));
        };
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: `self.event` is this PipeIo's own auto-reset event, set as
        // `overlapped.hEvent` by the caller before submitting the I/O.
        let waited = unsafe { WaitForSingleObject(self.event, millis) };
        if waited == WAIT_OBJECT_0 {
            // SAFETY: the event is signalled, so the operation has completed.
            return unsafe { GetOverlappedResult(self.pipe, overlapped, transferred, false) }
                .map_err(|e| std::io::Error::from_raw_os_error(e.code().0));
        }
        // SAFETY: cancels only this operation on this handle, then blocks until
        // the kernel is done with `overlapped` — see the note above.
        unsafe {
            let _ = CancelIoEx(self.pipe, Some(&*overlapped));
            let _ = GetOverlappedResult(self.pipe, overlapped, transferred, true);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "named pipe I/O exceeded its window",
        ))
    }
}

impl Drop for PipeIo {
    fn drop(&mut self) {
        if !self.event.is_invalid() {
            // SAFETY: event handle came from CreateEventW in `new`.
            unsafe {
                let _ = CloseHandle(self.event);
            }
        }
    }
}

// SAFETY: PipeIo wraps a raw HANDLE which is `*mut c_void` and not
// auto-`Send`. PipeIo must move into a reader sub-thread so the main
// connection loop can use `mpsc::recv_timeout` to interleave
// request dispatch with EventBus push pumps. The handle is exclusively
// owned by whichever thread holds the PipeIo at any moment — the main
// thread keeps a writer-side PipeIo while the reader thread owns its
// own (built from the same HANDLE; with FILE_FLAG_OVERLAPPED the two
// concurrent I/Os do not serialise at the kernel I/O lock).
unsafe impl Send for PipeIo {}

impl Read for PipeIo {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::ReadFile;
        // SAFETY: OVERLAPPED is zeroed; we set hEvent before submitting.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        // SAFETY: pipe is a valid overlapped handle for the lifetime of
        // this PipeIo; overlapped+event live on the stack until the
        // wait completes via GetOverlappedResult.
        let result = unsafe { ReadFile(self.pipe, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes_read: u32 = 0;
        match result {
            Ok(()) => {
                unsafe {
                    GetOverlappedResult(self.pipe, &overlapped, &mut bytes_read, false)
                        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes_read as usize)
            }
            Err(_) => {
                let last = unsafe { windows::Win32::Foundation::GetLastError().0 };
                // ERROR_IO_PENDING (997) — wait for completion.
                if last == 997 {
                    self.await_overlapped(&mut overlapped, &mut bytes_read)?;
                    Ok(bytes_read as usize)
                } else {
                    Err(std::io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }
}

impl Write for PipeIo {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Storage::FileSystem::WriteFile;
        // SAFETY: same lifetime contract as `read` above.
        let mut overlapped: OVERLAPPED = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
        overlapped.hEvent = self.event;
        let result = unsafe { WriteFile(self.pipe, Some(buf), None, Some(&mut overlapped)) };
        let mut bytes_written: u32 = 0;
        match result {
            Ok(()) => {
                unsafe {
                    GetOverlappedResult(self.pipe, &overlapped, &mut bytes_written, false)
                        .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
                }
                Ok(bytes_written as usize)
            }
            Err(_) => {
                let last = unsafe { windows::Win32::Foundation::GetLastError().0 };
                if last == 997 {
                    self.await_overlapped(&mut overlapped, &mut bytes_written)?;
                    Ok(bytes_written as usize)
                } else {
                    Err(std::io::Error::from_raw_os_error(last as i32))
                }
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        use windows::Win32::Storage::FileSystem::FlushFileBuffers;
        // SAFETY: pipe is a valid handle.
        unsafe { FlushFileBuffers(self.pipe) }
            .map_err(|e: windows::core::Error| std::io::Error::from_raw_os_error(e.code().0))
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_service_runtime::{IpcHandlerRegistry, NoopIpcAuditEmitter};

    #[test]
    fn pipe_name_is_versioned() {
        assert!(PIPE_NAME.ends_with("-v1"));
        assert!(PIPE_NAME.starts_with(r"\\.\pipe\"));
    }

    #[test]
    fn max_concurrent_connections_is_documented_value() {
        assert_eq!(MAX_CONCURRENT_CONNECTIONS, 32);
    }

    fn empty_router() -> Arc<IpcRouter> {
        let reg = IpcHandlerRegistry::new();
        let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
        Arc::new(IpcRouter::new(reg, audit, 1))
    }

    fn empty_audit() -> Arc<dyn IpcAuditEmitter> {
        Arc::new(NoopIpcAuditEmitter)
    }

    /// Bind builds the security descriptor and returns an acceptor
    /// without performing any pipe I/O. Drop must not panic.
    #[test]
    fn bind_returns_acceptor_with_no_io_side_effects() {
        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor = server.bind().expect("bind succeeds");
        // Immediate request_shutdown is idempotent and safe before any tick.
        acceptor.request_shutdown();
        acceptor.request_shutdown();
        // Drop runs the same shutdown signal harmlessly.
    }

    /// Calling `accept_one` after `request_shutdown` short-circuits to
    /// `ShutdownRequested` without doing any pipe work.
    #[test]
    fn accept_one_after_request_shutdown_returns_shutdown() {
        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor = server.bind().expect("bind succeeds");
        acceptor.request_shutdown();
        match acceptor.accept_one() {
            AcceptOutcome::ShutdownRequested => {}
            other => panic!("expected ShutdownRequested, got {other:?}"),
        }
    }

    /// Calling `join_workers` on an acceptor that never spawned any
    /// workers is a no-op and must not block or panic.
    #[test]
    fn join_workers_with_no_workers_is_noop() {
        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor = server.bind().expect("bind succeeds");
        acceptor.join_workers();
        acceptor.request_shutdown();
        acceptor.join_workers();
    }

    #[test]
    fn bind_can_be_called_multiple_times() {
        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let a = server.bind().expect("first bind");
        a.request_shutdown();
        drop(a);
        let b = server.bind().expect("second bind");
        b.request_shutdown();
    }

    // ── Real-pipe smoke tests ────────────────────────────────────────────
    //
    // These tests exercise the full Win32 transport — CreateNamedPipeW,
    // ConnectNamedPipe, real client via CreateFileW, identity check,
    // wire codec — using the canonical PIPE_NAME. Multiple tests cannot
    // safely run in parallel against the same PIPE_NAME, so we serialise
    // them through a process-wide mutex. Each test also sets a generous
    // timeout so a hang in one tick cannot stall the whole runner.

    use std::sync::OnceLock;
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};

    fn pipe_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        let m = LOCK.get_or_init(|| std::sync::Mutex::new(()));
        let guard = m.lock().unwrap_or_else(|p| p.into_inner());
        // An installed service owns the same canonical pipe name, so the test
        // client below connects to IT while this test's acceptor waits for a
        // connection that never arrives — the run hangs instead of failing.
        // Fail loudly with the one instruction that fixes it.
        if service_pipe_is_live() {
            panic!(
                "a NetRuleRouter service instance already owns {PIPE_NAME} — \
                 stop the service before running the pipe tests"
            );
        }
        guard
    }

    /// Is somebody already serving the canonical pipe?
    ///
    /// A successful open is the obvious yes. So is a REFUSED one: a pipe whose
    /// instances are all taken answers `ERROR_PIPE_BUSY`, and one whose DACL
    /// keeps this process out answers `ERROR_ACCESS_DENIED` — in both cases the
    /// name IS served, which is exactly what must stop the tests. Only "no such
    /// file / path" means it is free. The first version of this probe took
    /// `CreateFileW(..).ok()` for the whole answer, so a live service read as an
    /// absent one and the tests this exists to stop still hung forever.
    fn service_pipe_is_live() -> bool {
        pipe_is_live(PIPE_NAME)
    }

    /// The question above, asked of any pipe name — so the classification can
    /// be tested against pipes whose state is known.
    fn pipe_is_live(name: &str) -> bool {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is null-terminated UTF-16 and outlives the call.
        let opened = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };
        match opened {
            Ok(handle) => {
                // SAFETY: the handle came from the successful open above and is
                // closed exactly once here.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                true
            }
            Err(e) => !pipe_absent(e.code()),
        }
    }

    /// Does this failure mean "there is no such pipe" rather than "you cannot
    /// have it right now"?
    fn pipe_absent(code: windows::core::HRESULT) -> bool {
        [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND]
            .into_iter()
            .any(|win32| code == windows::core::HRESULT::from_win32(win32.0))
    }

    #[test]
    fn a_pipe_that_refuses_the_open_still_counts_as_served() {
        // `\\.\pipe\lsass` exists on every Windows install and refuses a
        // non-privileged open. That is the shape of a live NetRuleRouter
        // service too, and the shape the first version of this probe read as
        // "nobody there" — which is why a full test run used to hang against a
        // running service instead of stopping with the message above.
        assert!(
            pipe_is_live(r"\\.\pipe\lsass"),
            "a present-but-refused pipe must read as served"
        );
        assert!(
            !pipe_is_live(r"\\.\pipe\nrr-name-that-nobody-serves"),
            "an absent pipe must read as free"
        );
    }

    /// Open a client side of `PIPE_NAME` from the test process. Used to
    /// exercise the server's accept path — the test exe is not on the
    /// identity whitelist, so the server replies with `Forbidden`, which
    /// is precisely the round-trip we want to assert.
    fn connect_test_client() -> windows::core::Result<HANDLE> {
        let wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        // Retry briefly: if the test thread races ahead of the server's
        // first CreateNamedPipeW, CreateFileW returns ERROR_FILE_NOT_FOUND.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: wide is null-terminated UTF-16; we open with standard
            // duplex access.
            let result = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_NONE,
                    None,
                    OPEN_EXISTING,
                    windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                    HANDLE::default(),
                )
            };
            match result {
                Ok(h) => return Ok(h),
                Err(e) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                    let _ = e;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// A private overlapped pipe pair, so the deadline can be exercised without
    /// the connection worker's identity check writing a frame first.
    fn overlapped_pipe_pair(suffix: &str) -> (HANDLE, HANDLE) {
        let name = format!(
            r"\\.\pipe\NetRuleRouter\test-{suffix}-{}",
            std::process::id()
        );
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is null-terminated UTF-16 and outlives the call; a null
        // security pointer means the default DACL, which is this user only.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                0,
                None,
            )
        };
        assert!(!server.is_invalid(), "test pipe created");
        // SAFETY: same name, opened while the instance above is listening.
        let client = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                HANDLE::default(),
            )
        }
        .expect("test client connects");
        (server, client)
    }

    /// The deadline exists so a peer that stops talking cannot park a worker
    /// thread — and with it one of the 32 connection slots — indefinitely.
    ///
    /// The second half is the part worth pinning: after a timeout the cancelled
    /// read must have been REAPED, not merely abandoned. An abandoned overlapped
    /// read leaves the kernel free to write into a stack frame that is already
    /// gone, and the only cheap observable proof that it did not is that the
    /// handle still behaves.
    #[test]
    fn a_read_past_its_deadline_gives_up_and_leaves_the_handle_usable() {
        let (server, client) = overlapped_pipe_pair("deadline");
        let mut io = PipeIo::new(server).expect("server io");
        io.set_timeout(Some(Duration::from_millis(150)));

        let started = Instant::now();
        let mut buf = [0u8; 32];
        let err = io.read(&mut buf).expect_err("nothing was ever sent");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the read returned on its own deadline, not on some other event"
        );

        // Same handle, now with data waiting: the cancelled read left nothing behind.
        let mut peer = PipeIo::new(client).expect("client io");
        peer.write_all(b"ping").expect("client writes");
        io.set_timeout(Some(Duration::from_secs(5)));
        let read = io.read(&mut buf).expect("the handle still reads");
        assert_eq!(&buf[..read], b"ping");

        // SAFETY: both handles are owned by this test.
        unsafe {
            let _ = CloseHandle(client);
            let _ = CloseHandle(server);
        }
    }

    /// With no deadline the wait is unbounded — that is the correct behaviour
    /// for a subscriber sitting quiet for hours, and the reason the window is
    /// opt-in rather than always on.
    #[test]
    fn a_pipe_without_a_deadline_does_not_time_out() {
        let (server, client) = overlapped_pipe_pair("no-deadline");
        let mut io = PipeIo::new(server).expect("server io");
        let mut peer = PipeIo::new(client).expect("client io");
        peer.write_all(b"pong").expect("client writes");
        let mut buf = [0u8; 32];
        let read = io.read(&mut buf).expect("read without a deadline");
        assert_eq!(&buf[..read], b"pong");
        // SAFETY: both handles are owned by this test.
        unsafe {
            let _ = CloseHandle(client);
            let _ = CloseHandle(server);
        }
    }

    /// Real-pipe roundtrip: bind → spawn supervisor that ticks once →
    /// connect a client from this test process → server identifies the
    /// caller as not-whitelisted and writes a Forbidden response → client
    /// reads the frame → request_shutdown → join_workers → drop.
    ///
    /// Validates the whole new tick path including ConnectNamedPipe wake,
    /// per-connection worker spawn, identity rejection, and wire codec.
    #[test]
    fn real_pipe_roundtrip_returns_forbidden_for_test_process() {
        let _guard = pipe_test_lock();

        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc_for_thread = Arc::clone(&acceptor);
        let supervisor = thread::spawn(move || acc_for_thread.accept_one());

        // Give the supervisor a moment to call CreateNamedPipeW + ConnectNamedPipe.
        thread::sleep(Duration::from_millis(50));

        let client = connect_test_client().expect("client connects to pipe");
        let mut io = PipeIo::new(client).expect("test PipeIo::new");

        // Server's identity check writes Forbidden frame on its own — the
        // test client just reads.
        let response: IpcResponseEnvelope = read_frame(&mut io).expect("read forbidden frame");
        assert!(!response.ok);
        let err = response.error.expect("error present");
        assert_eq!(err.code, IpcErrorCode::Forbidden);
        assert!(err.message.contains("client rejected"));

        // SAFETY: client handle owned by this test.
        unsafe {
            let _ = CloseHandle(client);
        }

        let outcome = supervisor.join().expect("supervisor thread");
        assert!(matches!(outcome, AcceptOutcome::Connected));

        acceptor.request_shutdown();
        acceptor.join_workers();
    }

    /// Pending `accept_one` returns `ShutdownRequested` after
    /// `request_shutdown` is called — supervisor's stop signal is honoured
    /// even when the tick is mid-`ConnectNamedPipe`.
    #[test]
    fn request_shutdown_unblocks_pending_accept_one() {
        let _guard = pipe_test_lock();

        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc_for_thread = Arc::clone(&acceptor);
        let started = Arc::new(AtomicBool::new(false));
        let started_clone = Arc::clone(&started);
        let supervisor = thread::spawn(move || {
            started_clone.store(true, Ordering::SeqCst);
            acc_for_thread.accept_one()
        });

        // Wait until the supervisor has at least started its tick. Without
        // a synchronisation point we could race past the started flag and
        // call request_shutdown before accept_one even runs.
        let deadline = Instant::now() + Duration::from_secs(2);
        while !started.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(100));

        acceptor.request_shutdown();

        let join_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if supervisor.is_finished() {
                break;
            }
            if Instant::now() >= join_deadline {
                panic!("supervisor did not unblock after request_shutdown");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let outcome = supervisor.join().expect("supervisor thread");
        assert!(
            matches!(outcome, AcceptOutcome::ShutdownRequested),
            "expected ShutdownRequested, got {outcome:?}",
        );

        acceptor.join_workers();
    }

    /// Two sequential clients each get a frame back. Validates that
    /// `accept_one` can be called repeatedly on the same acceptor and
    /// produce independent worker threads.
    #[test]
    fn multiple_sequential_clients_each_receive_response() {
        let _guard = pipe_test_lock();

        let server = WindowsNamedPipeServer::new(empty_router(), empty_audit());
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        for round in 0..2 {
            let acc_for_thread = Arc::clone(&acceptor);
            let supervisor = thread::spawn(move || acc_for_thread.accept_one());

            thread::sleep(Duration::from_millis(50));

            let client = connect_test_client().expect("client connects");
            let mut io = PipeIo::new(client).expect("test PipeIo::new");
            let response: IpcResponseEnvelope =
                read_frame(&mut io).unwrap_or_else(|_| panic!("round {round} read"));
            assert!(!response.ok, "round {round} should be Forbidden");
            assert_eq!(response.error.unwrap().code, IpcErrorCode::Forbidden);
            // SAFETY: client owned by test.
            unsafe {
                let _ = CloseHandle(client);
            }

            let outcome = supervisor.join().expect("supervisor join");
            assert!(
                matches!(outcome, AcceptOutcome::Connected),
                "round {round} expected Connected, got {outcome:?}",
            );
        }

        acceptor.request_shutdown();
        acceptor.join_workers();
    }
}
