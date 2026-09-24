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

/// Hard ceiling on one response read — the Unix twin of the Windows client's
/// deadline. Above the slowest operation the service admits (a mutation
/// budgets 30 s): it ends waits that will never be answered, not slow ones.
const RESPONSE_READ_TIMEOUT: Duration = Duration::from_secs(60);

// ── Public client ────────────────────────────────────────────────────────────

/// Sync `AF_UNIX` IPC client. Cheap to clone — state lives behind `Arc`.
#[derive(Clone)]
pub struct UnixIpcClient {
    inner: Arc<ClientInner>,
    /// Held only by client handles, so its strong count counts USERS — see
    /// [`ClientLifetime`].
    #[allow(
        dead_code,
        reason = "held for its Drop: ends the worker with the last handle"
    )]
    lifetime: Arc<ClientLifetime>,
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
        let lifetime = Arc::new(ClientLifetime {
            inner: Arc::clone(&inner),
        });
        Self { inner, lifetime }
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
        let abandoned = Arc::new(AtomicBool::new(false));
        let pending = PendingRequest {
            envelope,
            response_tx: tx,
            abandoned: Arc::clone(&abandoned),
        };

        // A full queue is a busy client, not a dead one — see the Windows twin.
        if let Err(e) = self.inner.request_tx.try_send(pending) {
            return Err(match e {
                std::sync::mpsc::TrySendError::Full(_) => IpcClientError::Timeout,
                std::sync::mpsc::TrySendError::Disconnected(_) => IpcClientError::Disconnected,
            });
        }

        match rx.recv_timeout(timeout) {
            Ok(RequestResponse::Ok(payload)) => Ok(payload),
            Ok(RequestResponse::ServerError { op, code, message }) => {
                Err(IpcClientError::ServerError { op, code, message })
            }
            Ok(RequestResponse::BadResponse(reason)) => Err(IpcClientError::BadResponse { reason }),
            Ok(RequestResponse::Disconnected) => Err(IpcClientError::Disconnected),
            Err(RecvTimeoutError::Timeout) => {
                abandoned.store(true, Ordering::SeqCst);
                Err(IpcClientError::Timeout)
            }
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

    /// Prepare a push-frame receiver (server-pushed `StatusUpdate` frames).
    /// It carries nothing until [`Self::commit_push`]; the channel currently in
    /// force keeps delivering until then. See [`crate::push_handover`] for why
    /// the hand-over has two phases.
    pub fn subscribe_push(&self) -> Receiver<Value> {
        let (tx, rx) = sync_channel::<Value>(64);
        if let Ok(mut g) = self.inner.pending_push_tx.lock() {
            *g = Some(tx);
        }
        rx
    }

    /// Put the prepared channel in force, the subscribe having been answered.
    pub fn commit_push(&self) {
        crate::push_handover::commit_pending_push(&self.inner.pending_push_tx, &self.inner.push_tx);
    }

    /// Discard the prepared channel — the subscribe did not go through.
    pub fn abandon_push(&self) {
        crate::push_handover::abandon_pending_push(&self.inner.pending_push_tx);
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

    fn commit_push(&self) {
        Self::commit_push(self);
    }

    fn abandon_push(&self) {
        Self::abandon_push(self);
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

/// Shuts the worker down when the last client handle goes away. The Windows
/// twin carries the same type for the same reason: counting `inner` could
/// never reach one, because the worker holds an `Arc<ClientInner>` of its own.
struct ClientLifetime {
    inner: Arc<ClientInner>,
}

impl Drop for ClientLifetime {
    fn drop(&mut self) {
        self.inner.shutdown.store(true, Ordering::SeqCst);
        if let Ok(mut g) = self.inner.worker_handle.lock() {
            if let Some(h) = g.take() {
                let _ = h.join();
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
    /// `Arc` because the timed stream watches it while blocked in a read —
    /// that is what makes shutdown prompt on a connection gone quiet.
    shutdown: Arc<AtomicBool>,
    force_reconnect: AtomicBool,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
    push_tx: Mutex<Option<SyncSender<Value>>>,
    /// Prepared by a subscribe, in force only once its call has been answered.
    pending_push_tx: Mutex<Option<SyncSender<Value>>>,
    /// A push frame was dropped because the subscriber's channel was full —
    /// see the Windows twin.
    push_gap: AtomicBool,
    /// Id the SERVICE currently knows this client's subscription by. A
    /// reconnect re-subscribes and is handed a fresh one, so anything that
    /// labels forwarded frames has to re-read it. Windows tracked this from
    /// the start; without it the launcher stamped every Linux push with the
    /// id captured when the forwarder started.
    subscription_id: Mutex<Option<String>>,
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
            shutdown: Arc::new(AtomicBool::new(false)),
            force_reconnect: AtomicBool::new(false),
            worker_handle: Mutex::new(None),
            push_tx: Mutex::new(None),
            pending_push_tx: Mutex::new(None),
            push_gap: AtomicBool::new(false),
            subscription_id: Mutex::new(None),
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
    /// Raised by the caller when it stops waiting — see the Windows twin.
    abandoned: Arc<AtomicBool>,
}

mod frames;
mod worker;

use worker::worker_loop;

#[cfg(test)]
mod tests;
