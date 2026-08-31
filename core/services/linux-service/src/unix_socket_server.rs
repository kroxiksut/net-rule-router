//! AF_UNIX IPC server — the Linux analog of
//! `windows-service/named_pipe_server.rs`.
//!
//! ## Why this is much simpler than the Windows pipe server
//!
//! A `UnixStream` is already `Read + Write + Send`, so — unlike the Windows
//! named pipe, which needs `FILE_FLAG_OVERLAPPED` + a `PipeIo` adapter + a
//! reader sub-thread to avoid kernel I/O-lock serialisation — the same generic
//! wire codec (`nrr_shared::ipc_wire`) reads and writes the socket directly.
//! The client side (`nrr-ipc-client::client_unix`) already proved this; this is
//! its server mirror.
//!
//! ## Model vs the Windows server (honest inversions)
//!
//! - **No exe-basename whitelist / no per-connection reject.** The Windows pipe
//!   accepts only `NetRuleRouter(.Tray).exe`; on Linux the connecting exe is not
//!   part of the peer credential, and there is no directory gate either: the
//!   daemon is root and its clients are ordinary users, so a `0700` runtime
//!   directory would lock out every client the product has. Any local user may
//!   reach the socket. That is not authority - identity is SO_PEERCRED
//!   (`unix:uid:<n>`), the rules a caller can touch are their own principal's,
//!   and privileged operations go through polkit.
//!   `peer_cred::classify_unix_client` resolves identity but never rejects on
//!   an exe basis.
//! - **Client profile defaults to `GuiInteractive`.** The Windows server derives
//!   `IpcClientProfile` from the exe basename; peer-cred cannot, so every caller
//!   is treated as the full-capability profile. Authorization that matters flows
//!   through `caller_principal` (`unix:uid:<n>`), `caller_is_elevated`
//!   (`uid == 0`) and — for privileged operations from an ordinary user — polkit,
//!   which the router consults using the pid captured here.
//!
//! ## Shutdown
//!
//! `accept_one` blocks on `UnixListener::accept`. `request_shutdown` flips the
//! flag and wakes the blocked accept by self-connecting to the socket (the same
//! technique the Windows server uses via `CreateFileW`). The tick then re-checks
//! the flag and returns `ShutdownRequested`.
//!
//! ## Push delivery
//!
//! A subscribed client is owed events it never asked for again, so the worker
//! cannot sit in a blocking read. `try_clone` gives the reader its own fd: a
//! sub-thread does blocking reads and forwards frames over an mpsc, and the main
//! loop alternates between dispatching what arrives and draining the `EventBus`
//! (`nrr_service_runtime::ipc_push`). Read timeouts would be simpler and wrong —
//! one expiring mid-frame loses the bytes already consumed and desynchronises
//! the stream.

#![cfg(target_os = "linux")]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nrr_platform_linux::peer_cred::classify_unix_client;
use nrr_service_runtime::ipc_push::{
    extract_subscription_id, flush_push_frames, PUSH_BATCH_SIZE, PUSH_POLL_INTERVAL,
};
use nrr_service_runtime::{
    AcceptError, AcceptErrorCategory, AcceptOutcome, EventBus, IpcAcceptor, IpcBindError, IpcError,
    IpcErrorCode, IpcRequestContext, IpcRequestEnvelope, IpcResponseEnvelope, IpcRouter, IpcServer,
    UserPrincipal,
};
use nrr_shared::ipc::IpcClientProfile;
use nrr_shared::ipc_wire::{read_frame, write_frame};

/// Canonical socket path — the cross-OS endpoint SSOT resolves to the Unix
/// socket form here (`/run/netrulerouter/service-v1.sock`), so server and client
/// can never drift.
pub const SOCKET_PATH: &str = nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;

/// Hard limit on concurrent connections (matches the Windows server).
pub const MAX_CONCURRENT_CONNECTIONS: usize = 32;

/// Profile assigned to every accepted caller — see the module doc for why the
/// Linux transport cannot distinguish GUI from tray and defaults to the
/// full-capability profile.
const DEFAULT_CLIENT_PROFILE: IpcClientProfile = IpcClientProfile::GuiInteractive;

/// How long a freshly accepted connection may stay silent before the slot is
/// taken back. Generous - a GUI starting on a cold machine is slower than one
/// might think - but finite, which is the whole point.
const FIRST_FRAME_IDLE_TIMEOUT: Duration = Duration::from_secs(20);

/// Production AF_UNIX IPC server. Holds the router it dispatches to and the
/// socket path to bind. Cheap to construct — the `UnixListener::bind` happens in
/// [`IpcServer::bind`].
pub struct UnixDomainSocketServer {
    router: Arc<IpcRouter>,
    socket_path: PathBuf,
    /// Shared bus the per-connection workers drain for their subscription.
    /// `None` leaves a subscribed client on request/response only.
    event_bus: Option<Arc<EventBus>>,
}

impl UnixDomainSocketServer {
    /// Construct a server bound to the canonical [`SOCKET_PATH`].
    pub fn new(router: Arc<IpcRouter>) -> Self {
        Self {
            router,
            socket_path: PathBuf::from(SOCKET_PATH),
            event_bus: None,
        }
    }

    /// Attach the shared `EventBus` so workers can flush push frames after a
    /// `StatusUpdatesSubscribe`.
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Construct a server bound to an explicit path — used by tests to bind a
    /// throwaway socket in a temp dir instead of the root-owned `/run` path.
    #[cfg(test)]
    fn new_at(router: Arc<IpcRouter>, socket_path: impl Into<PathBuf>) -> Self {
        Self {
            router,
            socket_path: socket_path.into(),
            event_bus: None,
        }
    }
}

impl IpcServer for UnixDomainSocketServer {
    fn bind(&self) -> Result<Box<dyn IpcAcceptor>, IpcBindError> {
        // The parent dir (`/run/netrulerouter`) is systemd's `RuntimeDirectory`
        // in production; create it best-effort so tests (and a non-systemd smoke
        // run) can bind too.
        if let Some(parent) = self.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
            // Traversable, set explicitly rather than left to the umask: under
            // systemd `RuntimeDirectoryMode` already says this, but a daemon
            // started any other way must not end up with a directory whose mode
            // depends on how the process was launched.
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
        }
        // A stale socket file from a previous run makes `bind` fail with
        // EADDRINUSE — remove it first (absence is fine).
        match std::fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(IpcBindError::Other(format!(
                    "cannot clear stale socket {}: {e}",
                    self.socket_path.display()
                )))
            }
        }
        let listener = UnixListener::bind(&self.socket_path).map_err(|e| {
            IpcBindError::Other(format!("bind {} failed: {e}", self.socket_path.display()))
        })?;
        // The socket is the permission surface, and it is set here rather than
        // inherited from the umask: the daemon is root, its clients are not, and
        // a socket that happened to come out 0755 would refuse every one of
        // them. Reaching the socket is not authority - identity is SO_PEERCRED
        // (`unix:uid:<n>`), rules are per principal, and privileged operations
        // go through polkit.
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o666))
            .map_err(|e| {
                IpcBindError::Other(format!(
                    "cannot set mode on {}: {e}",
                    self.socket_path.display()
                ))
            })?;
        // Identity of the node we just created. `Drop` unlinks only if the path
        // still resolves to it: an accept-error rebind creates a NEW socket at
        // the same path while the failed acceptor is still alive, and its
        // unlink would delete the replacement, leaving the daemon listening on
        // an anonymous inode with every client getting ENOENT until the unit is
        // restarted.
        let node = std::fs::metadata(&self.socket_path)
            .map(|m| (m.dev(), m.ino()))
            .map_err(|e| {
                IpcBindError::Other(format!("cannot stat {}: {e}", self.socket_path.display()))
            })?;
        Ok(Box::new(UnixDomainSocketAcceptor {
            listener,
            node,
            router: Arc::clone(&self.router),
            event_bus: self.event_bus.clone(),
            socket_path: self.socket_path.clone(),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            active_count: Arc::new(AtomicUsize::new(0)),
            worker_handles: Arc::new(Mutex::new(Vec::new())),
        }))
    }
}

/// Acceptor produced by [`UnixDomainSocketServer::bind`]. Owns the bound
/// listener and the shared shutdown state.
pub struct UnixDomainSocketAcceptor {
    listener: UnixListener,
    router: Arc<IpcRouter>,
    event_bus: Option<Arc<EventBus>>,
    /// The bound path, kept so `request_shutdown` can self-connect to wake a
    /// blocked `accept`, and `Drop` can unlink the socket file.
    socket_path: PathBuf,
    /// `(dev, ino)` of the node this acceptor created, so `Drop` can tell our
    /// socket from a replacement bound at the same path.
    node: (u64, u64),
    shutdown_requested: Arc<AtomicBool>,
    active_count: Arc<AtomicUsize>,
    worker_handles: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl IpcAcceptor for UnixDomainSocketAcceptor {
    fn accept_one(&self) -> AcceptOutcome {
        if self.shutdown_requested.load(Ordering::SeqCst) {
            return AcceptOutcome::ShutdownRequested;
        }

        let stream = match self.listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                return AcceptOutcome::Err(AcceptError {
                    category: AcceptErrorCategory::Other,
                    message: format!("accept failed: {e}"),
                })
            }
        };

        // Re-check shutdown: the wake may have been our own self-connect from
        // `request_shutdown`, not a real client.
        if self.shutdown_requested.load(Ordering::SeqCst) {
            drop(stream);
            return AcceptOutcome::ShutdownRequested;
        }

        // Throttle: busy-close if at the concurrency cap. Idle — the supervisor
        // keeps ticking without charging the retry budget.
        if self.active_count.load(Ordering::SeqCst) >= MAX_CONCURRENT_CONNECTIONS {
            let _ = write_busy_response(stream);
            return AcceptOutcome::Idle;
        }

        let router = Arc::clone(&self.router);
        let bus = self.event_bus.clone();
        // A guard, so a panic in dispatch cannot leak the slot - see
        // `connection_slot`.
        let slot = nrr_service_runtime::connection_slot::ConnectionSlot::claim(Arc::clone(
            &self.active_count,
        ));
        let spawn = thread::Builder::new()
            .name("nrr-ipc-worker".into())
            .spawn(move || {
                let _slot = slot;
                handle_connection(stream, router, bus);
            });

        match spawn {
            Ok(handle) => {
                if let Ok(mut guard) = self.worker_handles.lock() {
                    guard.retain(|j| !j.is_finished());
                    guard.push(handle);
                }
                AcceptOutcome::Connected
            }
            Err(e) => {
                // The guard went with the failed closure and released the slot.
                AcceptOutcome::Err(AcceptError {
                    category: AcceptErrorCategory::WorkerSpawn,
                    message: format!("worker thread spawn failed: {e}"),
                })
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        // Wake a blocked `accept` by self-connecting. Best-effort: if nothing is
        // blocked, the connection is simply accepted and dropped on the
        // shutdown re-check.
        let _ = UnixStream::connect(&self.socket_path);
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

impl Drop for UnixDomainSocketAcceptor {
    fn drop(&mut self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        // Unlink OUR node only. If the path now resolves to a different inode,
        // somebody rebound while we were still alive and the file belongs to
        // them.
        let still_ours = std::fs::metadata(&self.socket_path)
            .map(|m| (m.dev(), m.ino()) == self.node)
            .unwrap_or(false);
        if still_ours {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// Frames the reader sub-thread hands to the dispatch loop.
enum ReaderMsg {
    Request(IpcRequestEnvelope),
    Malformed,
    Closed,
}

/// Per-connection worker: classify the caller once, then serve framed
/// request→response pairs — interleaved with push flushes once the client
/// subscribes — until it disconnects or a frame is malformed.
fn handle_connection(
    mut stream: UnixStream,
    router: Arc<IpcRouter>,
    event_bus: Option<Arc<EventBus>>,
) {
    let identity = match classify_unix_client(&stream) {
        Ok(id) => id,
        Err(_) => return, // getsockopt failure — nothing we can attribute; drop.
    };
    let principal: Option<UserPrincipal> = Some(identity.principal.clone());
    // Peer credentials name the user, not the program, so this starts at the
    // full profile and can only be narrowed — by what the caller declares in its
    // handshake (see `narrow_profile_from_handshake`). A caller that declares
    // nothing keeps the default; a caller that declares itself a console is held
    // to a console's limits for the rest of the connection.
    let mut profile = DEFAULT_CLIENT_PROFILE;

    let mut reader = match stream.try_clone() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target: "nrr::ipc", error = %e, "socket clone failed, dropping connection");
            return;
        }
    };
    let (reader_tx, reader_rx) = std::sync::mpsc::sync_channel::<ReaderMsg>(8);
    // Idle timeout for the FIRST frame only. A connection that says nothing
    // holds one of 32 slots for as long as it likes, and 32 silent connections
    // make the service unreachable without a single malformed byte. After the
    // first frame the timeout comes off: a subscriber legitimately sits quiet
    // for hours waiting to be pushed to, and cutting it would break the very
    // thing the connection is for.
    let _ = reader.set_read_timeout(Some(FIRST_FRAME_IDLE_TIMEOUT));
    let reader_thread = thread::Builder::new()
        .name("nrr-ipc-reader".into())
        .spawn(move || {
            let mut first = true;
            loop {
                let msg = match read_frame::<_, IpcRequestEnvelope>(&mut reader) {
                    Ok(req) => ReaderMsg::Request(req),
                    Err(e) if e.is_transport_dead() => ReaderMsg::Closed,
                    Err(_) if first => {
                        // Nothing arrived in the window - including a read that
                        // timed out, which `read_frame` reports as a broken
                        // frame. Treat it as a client that never introduced
                        // itself and give the slot back.
                        ReaderMsg::Closed
                    }
                    Err(_) => ReaderMsg::Malformed,
                };
                if first {
                    first = false;
                    let _ = reader.set_read_timeout(None);
                }
                let terminal = !matches!(msg, ReaderMsg::Request(_));
                if reader_tx.send(msg).is_err() || terminal {
                    break;
                }
            }
        })
        .ok();

    let mut subscription_id: Option<String> = None;
    loop {
        match reader_rx.recv_timeout(PUSH_POLL_INTERVAL) {
            Ok(ReaderMsg::Request(request)) => {
                profile = narrow_profile_from_handshake(profile, &request);
                let ctx = IpcRequestContext {
                    client_profile: profile,
                    caller_is_elevated: identity.caller_is_elevated,
                    caller_principal: principal.clone(),
                    // Named so the router can ask polkit about this caller: on
                    // this platform an ordinary user cannot elevate a client,
                    // and being authorized for the one action is how they get
                    // to do privileged work at all.
                    caller_pid: u32::try_from(identity.pid).ok(),
                };
                let response = router.dispatch(request, ctx);
                if subscription_id.is_none() && response.ok {
                    subscription_id = extract_subscription_id(&response);
                    if let Some(sub_id) = subscription_id.as_deref() {
                        tracing::info!(
                            target: "nrr::ipc-push",
                            subscription_id = sub_id,
                            bus_wired = event_bus.is_some(),
                            "push subscription opened"
                        );
                    }
                }
                if write_frame(&mut stream, &response).is_err() {
                    break;
                }
            }
            Ok(ReaderMsg::Malformed) => {
                let _ = write_frame(
                    &mut stream,
                    &error_response(IpcErrorCode::MalformedRequest, "frame decode failed"),
                );
                break;
            }
            Ok(ReaderMsg::Closed) => break, // EOF / client closed.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if let (Some(sub_id), Some(bus)) = (subscription_id.as_ref(), event_bus.as_ref()) {
                    let failed = flush_push_frames(bus, sub_id, PUSH_BATCH_SIZE, |env| {
                        write_frame(&mut stream, env).map_err(|e| e.to_string())
                    });
                    if failed {
                        break;
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Stop the bus accumulating for a subscription nobody will read.
    if let (Some(sub_id), Some(bus)) = (subscription_id.as_ref(), event_bus.as_ref()) {
        bus.unsubscribe(sub_id);
        tracing::info!(
            target: "nrr::ipc-push",
            subscription_id = %sub_id,
            subscribers = bus.subscriber_count(),
            "push subscription closed"
        );
    }
    // The reader holds its own dup of the fd, so dropping ours would leave it
    // blocked until the client happened to disconnect. Shut the socket down
    // instead: the pending read returns EOF and the thread joins at once.
    let _ = stream.shutdown(std::net::Shutdown::Both);
    // Release the queue too: a reader parked in `send` (bounded channel, nobody
    // receiving any more) unblocks with an error and falls out of its loop.
    drop(reader_rx);
    if let Some(handle) = reader_thread {
        let _ = handle.join();
    }
}

/// Apply a `contract.negotiate` handshake's declared client kind to the
/// connection's profile.
///
/// Narrowing only, and permanently for the connection: a caller cannot regain
/// capability by declaring something wider later, nor by declaring twice. Any
/// other operation, or an unparseable handshake payload, leaves the profile
/// untouched — a declaration is an opportunity to be trusted less, never a
/// requirement.
fn narrow_profile_from_handshake(
    current: IpcClientProfile,
    request: &IpcRequestEnvelope,
) -> IpcClientProfile {
    use nrr_shared::ipc::IpcOperationName;
    use nrr_shared::ipc_payloads::ContractNegotiateRequest;

    if request.operation != IpcOperationName::ContractNegotiate {
        return current;
    }
    match serde_json::from_value::<ContractNegotiateRequest>(request.payload.clone()) {
        Ok(negotiate) => current.narrowed_by(negotiate.client_kind.declared_ceiling()),
        Err(_) => current,
    }
}

/// Synthetic response written when the concurrency cap rejects a connection
/// before any protocol exchange.
fn write_busy_response(mut stream: UnixStream) -> std::io::Result<()> {
    let env = error_response(
        IpcErrorCode::Internal,
        "service is busy; max concurrent connections reached",
    );
    write_frame(&mut stream, &env).map_err(std::io::Error::other)
}

/// Build a well-formed error [`IpcResponseEnvelope`] (empty ids — these are
/// transport-level errors not tied to a decoded request).
fn error_response(code: IpcErrorCode, message: &str) -> IpcResponseEnvelope {
    IpcResponseEnvelope {
        request_id: String::new(),
        correlation_id: String::new(),
        operation_id: None,
        ok: false,
        stale: false,
        diagnostics_id: None,
        user_action_required: false,
        payload: None,
        error: Some(IpcError {
            code,
            message: message.to_string(),
            diagnostics_id: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_service_runtime::{IpcAuditEmitter, IpcHandlerRegistry, NoopIpcAuditEmitter};
    use std::sync::atomic::AtomicU32;
    use std::time::{Duration, Instant};

    /// Hand-rolled temp dir (zero dev-deps, same idiom as `peer_cred`).
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_dir() -> TempDir {
        static N: AtomicU32 = AtomicU32::new(0);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "nrr-unixsrv-test-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        TempDir(p)
    }

    fn empty_router() -> Arc<IpcRouter> {
        let reg = IpcHandlerRegistry::new();
        let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
        Arc::new(IpcRouter::new(reg, audit, 1))
    }

    /// The daemon's own registry, over a caller-supplied bus so a test can
    /// publish into the same one the workers drain.
    fn serving_router(event_bus: Arc<EventBus>) -> Arc<IpcRouter> {
        let audit: Arc<dyn IpcAuditEmitter> = Arc::new(NoopIpcAuditEmitter);
        let health = Arc::new(nrr_service_runtime::HealthAggregator::new());
        Arc::new(IpcRouter::new(
            crate::run::serving_registry_with(health, event_bus),
            audit,
            1,
        ))
    }

    /// Connect with a retry window — the acceptor may not have reached
    /// `accept` yet when the test's client dials.
    fn connect(sock: &std::path::Path) -> UnixStream {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match UnixStream::connect(sock) {
                Ok(s) => return s,
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("client connect failed: {e}"),
            }
        }
    }

    fn sample_request() -> IpcRequestEnvelope {
        request_for(nrr_shared::ipc::IpcOperationName::ContractNegotiate)
    }

    /// The class is DERIVED, the way the client derives it and the way the
    /// router admits it: a hand-picked one is refused as a malformed envelope.
    fn request_for(operation: nrr_shared::ipc::IpcOperationName) -> IpcRequestEnvelope {
        let payload = serde_json::json!({});
        IpcRequestEnvelope {
            protocol_version: 1,
            request_id: "req-1".into(),
            correlation_id: None,
            operation,
            operation_class: nrr_service_runtime::ipc::canonical_operation_class(
                operation, &payload,
            ),
            confirmation_token: None,
            payload,
        }
    }

    /// An accept error rebinds: the failed acceptor is still alive while the
    /// replacement binds a NEW socket at the same path, and the old one's
    /// unlink used to delete it. The daemon then listened on an anonymous inode
    /// and every client got ENOENT until the unit was restarted, while health
    /// reported a successful rebind.
    /// A connection that says nothing holds one of 32 slots for as long as it
    /// likes. Thirty-two silent connections make the service unreachable
    /// without sending a single malformed byte.
    #[test]
    fn a_connection_that_never_speaks_gives_its_slot_back() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc = Arc::clone(&acceptor);
        let ticker = thread::spawn(move || acc.accept_one());
        // Connect and stay silent.
        let quiet = connect(&sock);
        assert!(matches!(
            ticker.join().expect("tick"),
            AcceptOutcome::Connected
        ));

        // The worker is parked on the first frame. Give it a moment and check
        // the slot is still held - the timeout is measured in seconds, so this
        // proves the guard is not released early.
        thread::sleep(Duration::from_millis(50));
        assert_eq!(acceptor.active_connections(), 1);
        drop(quiet);
        // A closed peer is the fast path out; the timeout covers the peer that
        // stays open and silent, which no unit test should wait 20 s for.
        for _ in 0..200 {
            if acceptor.active_connections() == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            acceptor.active_connections(),
            0,
            "the worker must release its slot once the peer goes away",
        );
    }

    #[test]
    fn a_rebind_does_not_lose_its_socket_to_the_acceptor_it_replaced() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);

        let first = server.bind().expect("first bind");
        let second = server.bind().expect("rebind");
        drop(first);

        assert!(
            sock.exists(),
            "the replacement's socket must survive the old acceptor's drop",
        );
        assert!(
            UnixStream::connect(&sock).is_ok(),
            "and still be connectable"
        );
        drop(second);
        assert!(!sock.exists(), "the last acceptor cleans up after itself");
    }

    /// The daemon runs as root and its clients do not, so a socket left at the
    /// umask's mercy refuses every client the product has.
    #[test]
    fn the_socket_is_reachable_by_an_ordinary_user() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor = server.bind().expect("bind");
        let mode = std::fs::metadata(&sock).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o666, "socket mode");
        let parent_mode = std::fs::metadata(dir.0.as_path())
            .expect("stat parent")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(parent_mode, 0o755, "runtime dir must be traversable");
        drop(acceptor);
    }

    #[test]
    fn socket_path_is_versioned_unix_socket() {
        assert!(SOCKET_PATH.ends_with("-v1.sock"));
        assert!(SOCKET_PATH.starts_with('/'));
    }

    #[test]
    fn bind_creates_the_socket_and_join_with_no_workers_is_noop() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor = server.bind().expect("bind");
        assert!(sock.exists(), "bind must create the socket node");
        acceptor.join_workers();
        acceptor.request_shutdown();
    }

    #[test]
    fn accept_one_after_request_shutdown_returns_shutdown() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor = server.bind().expect("bind");
        acceptor.request_shutdown();
        match acceptor.accept_one() {
            AcceptOutcome::ShutdownRequested => {}
            other => panic!("expected ShutdownRequested, got {other:?}"),
        }
    }

    /// Full transport round-trip: bind a temp socket, tick the acceptor on a
    /// thread, connect a real client, send a framed request, and read the
    /// framed response. The empty router replies with an error (no handler
    /// registered), which still proves accept → peer_cred → read_frame →
    /// dispatch → write_frame end to end.
    #[test]
    fn real_socket_roundtrip_dispatches_and_responds() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc = Arc::clone(&acceptor);
        let ticker = thread::spawn(move || acc.accept_one());

        // Connect a real client and exchange one framed request/response.
        let mut client = connect(&sock);
        write_frame(&mut client, &sample_request()).expect("client writes request");
        let response: IpcResponseEnvelope = read_frame(&mut client).expect("client reads response");
        // Empty registry → the op is unhandled → a well-formed error envelope.
        assert!(!response.ok);
        assert!(response.error.is_some());

        // Client drop → server worker sees EOF and exits.
        drop(client);

        let outcome = ticker.join().expect("ticker thread");
        assert!(
            matches!(outcome, AcceptOutcome::Connected),
            "got {outcome:?}"
        );

        acceptor.request_shutdown();
        acceptor.join_workers();
    }

    /// The daemon's real registry answers the handshake instead of refusing it.
    ///
    /// The distinction this pins down: an "unhandled operation" error and a
    /// broken transport look identical to a client, so a daemon that only ever
    /// errors is indistinguishable from one that never connected.
    #[test]
    fn the_serving_registry_answers_the_handshake() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let router = serving_router(Arc::new(EventBus::new()));
        let server = UnixDomainSocketServer::new_at(router, &sock);
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc = Arc::clone(&acceptor);
        let ticker = thread::spawn(move || acc.accept_one());

        let mut client = connect(&sock);
        // A real handshake payload — the empty one the transport test uses is
        // rejected by the handler, which would prove nothing about routing.
        let mut request = sample_request();
        request.payload = serde_json::json!({
            "client-version": 1,
            "client-kind": "gui",
            "supported-features": [],
        });
        write_frame(&mut client, &request).expect("client writes request");
        let response: IpcResponseEnvelope = read_frame(&mut client).expect("client reads response");
        assert!(
            response.ok,
            "contract.negotiate must be answered, got {:?}",
            response.error
        );

        drop(client);
        let _ = ticker.join().expect("ticker thread");
        acceptor.request_shutdown();
        acceptor.join_workers();
    }

    /// A subscribed client is handed events it never asked for again.
    ///
    /// The distinction that matters: without the pump the connection still
    /// answers `status.updates.subscribe` with a subscription id, so a client
    /// sees a healthy subscription and silently never receives anything.
    #[test]
    fn a_subscribed_client_receives_a_published_event_as_a_push_frame() {
        use nrr_shared::ipc::IpcOperationName;
        use nrr_shared::ipc_payloads::{StatusUpdateEvent, StatusUpdatePushFrame};

        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let bus = Arc::new(EventBus::new());
        let server = UnixDomainSocketServer::new_at(serving_router(Arc::clone(&bus)), &sock)
            .with_event_bus(Arc::clone(&bus));
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc = Arc::clone(&acceptor);
        let ticker = thread::spawn(move || acc.accept_one());

        let mut client = connect(&sock);
        let mut request = request_for(IpcOperationName::StatusUpdatesSubscribe);
        request.payload = serde_json::json!({ "client-id": "test-client" });
        write_frame(&mut client, &request).expect("client writes subscribe");
        let response: IpcResponseEnvelope = read_frame(&mut client).expect("client reads response");
        assert!(
            response.ok,
            "subscribe must succeed, got {:?}",
            response.error
        );

        // Publish AFTER the subscription exists, so the frame can only arrive
        // via the pump rather than as part of the response.
        let event_id = bus.publish(StatusUpdateEvent::AdaptersChanged {
            data_source: "netlink".into(),
        });
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let push: IpcResponseEnvelope = read_frame(&mut client).expect("client reads push frame");
        assert!(push.request_id.is_empty(), "a push answers no request");
        assert_eq!(
            push.correlation_id,
            extract_subscription_id(&response).expect("sub id")
        );
        let frame: StatusUpdatePushFrame =
            serde_json::from_value(push.payload.expect("push payload")).expect("decode push");
        assert_eq!(frame.event_id, event_id);

        drop(client);
        let _ = ticker.join().expect("ticker thread");
        acceptor.request_shutdown();
        acceptor.join_workers();
    }

    /// `request_shutdown` unblocks a pending `accept_one` (via self-connect)
    /// even when no real client ever arrives.
    #[test]
    fn request_shutdown_unblocks_pending_accept() {
        let dir = temp_dir();
        let sock = dir.0.join("service.sock");
        let server = UnixDomainSocketServer::new_at(empty_router(), &sock);
        let acceptor: Arc<dyn IpcAcceptor> = Arc::from(server.bind().expect("bind"));

        let acc = Arc::clone(&acceptor);
        let ticker = thread::spawn(move || acc.accept_one());
        // Let the ticker reach the blocking accept.
        thread::sleep(Duration::from_millis(100));
        acceptor.request_shutdown();

        let deadline = Instant::now() + Duration::from_secs(5);
        while !ticker.is_finished() {
            if Instant::now() >= deadline {
                panic!("accept did not unblock after request_shutdown");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let outcome = ticker.join().expect("ticker thread");
        assert!(
            matches!(outcome, AcceptOutcome::ShutdownRequested),
            "got {outcome:?}"
        );
        acceptor.join_workers();
    }
}
