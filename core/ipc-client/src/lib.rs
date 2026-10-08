//! `nrr-ipc-client` — Named Pipes IPC client used by GUI and tray.
//!
//! Sync API + background reader thread + reconnect state machine over
//! Windows Named Pipes. The wire codec is identical to the server's — both
//! ends share `IPC_MAX_MESSAGE_BYTES` from `nrr-shared::ipc_transport` and
//! the same length-prefixed JSON frame.
//!
//! ## Usage
//!
//! ```ignore
//! use nrr_ipc_client::{NamedPipeIpcClient, ConnectionStatus};
//! use nrr_shared::ipc::IpcOperationName;
//!
//! let client = NamedPipeIpcClient::start();
//! match client.connection_status() {
//!     ConnectionStatus::Connected => { /* ready */ }
//!     ConnectionStatus::ServiceNotInstalled => { /* show install button */ }
//!     ConnectionStatus::Disconnected { .. } => { /* reconnect happens automatically */ }
//!     _ => {}
//! }
//!
//! let response = client.call(
//!     IpcOperationName::ServiceHealthGet,
//!     serde_json::json!({}),
//!     std::time::Duration::from_secs(2),
//! )?;
//! ```
//!
//! ## Crate boundaries
//!
//! Depends on `nrr-shared` only. Everything above the transport — the GUI's
//! backend facade, preview snapshots — lives in the crates that use it, so the
//! console and the broker link the client without the desktop layers.

pub mod connection;
/// Transport-neutral IPC protocol layer: envelope building, operation-class
/// resolution, handshake/response parsing. Shared by the Windows named-pipe
/// client and the Unix `AF_UNIX` client so the wire protocol has one
/// definition (policy) independent of the byte carrier (mechanism).
/// Crate-internal.
mod protocol;
#[cfg(target_os = "windows")]
pub mod scm_probe;
pub mod snapshot_cache;
/// The frame codec now lives in `nrr-shared`, where both ends of the protocol
/// can reach it without a server depending on the client. Re-exported under the
/// old path so client-side call sites are unchanged.
pub use nrr_shared::ipc_wire as wire;
pub mod wire_error;

#[cfg(target_os = "windows")]
mod transport;

/// Only the Windows client consumes it; the decision is tested on every host.
#[cfg(any(target_os = "windows", test))]
mod server_identity;

/// Unix `AF_UNIX` transport primitive. Public so it is a discoverable
/// building block for the Unix client; the Windows `transport` stays
/// private because only `client` consumes it.
#[cfg(unix)]
pub mod transport_unix;

mod push_handover;

/// Set by [`silence_diagnostics`]; read by the client's stderr trace.
static DIAGNOSTICS_SILENCED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Stop the client's stderr trace. For a process that owns the terminal: a
/// full-screen or screen-reader interface would get the lines in its output.
pub fn silence_diagnostics() {
    DIAGNOSTICS_SILENCED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// `eprintln!` unless the process silenced the client. The one stderr path
/// of both clients, so [`silence_diagnostics`] holds on every OS.
macro_rules! client_trace {
    ($($arg:tt)*) => {
        if !$crate::DIAGNOSTICS_SILENCED.load(::std::sync::atomic::Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}

#[cfg(target_os = "windows")]
mod client;

/// Unix `AF_UNIX` reconnect client — the sibling of the Windows
/// `NamedPipeIpcClient`. Reuses the neutral [`protocol`] layer and the
/// [`connection`] state machine; the transport is `transport_unix`. No SCM
/// probe: on Linux the service lifecycle is systemd's, so a failed connect
/// simply backs off and retries.
#[cfg(unix)]
mod client_unix;

#[cfg(unix)]
pub use client_unix::UnixIpcClient;

mod timeouts;

#[cfg(target_os = "windows")]
pub use client::NamedPipeIpcClient;
pub use timeouts::ipc_operation_timeout;

/// The transport this OS talks to the service over. One name for the two
/// implementations, so callers that only need "the client" name this and carry
/// no `cfg` of their own.
/// Both sides expose the same surface (`start`, `call`, `connection_status`,
/// `force_reconnect`, `subscribe_push`, `negotiate_info`, `shutdown`).
#[cfg(target_os = "windows")]
pub type ServiceIpcClient = NamedPipeIpcClient;

/// See the Windows spelling above.
#[cfg(unix)]
pub type ServiceIpcClient = UnixIpcClient;
pub use connection::{ConnectionStatus, IpcClient, IpcClientError, NegotiateInfo};
/// Declare what this process is before it connects — see the item's own docs.
pub use protocol::declare_client_kind;
pub use wire::{read_frame, write_frame, WireError};
pub use wire_error::ipc_error_to_wire;

/// Canonical Windows pipe path for the `service-v1` protocol. Derived from
/// the cross-OS endpoint SSOT in `nrr-shared::ipc_transport` so the client,
/// the service, and the (future) Unix socket path never drift. Consumed only
/// by the `#[cfg(target_os = "windows")]` transport; on Unix the SSOT resolves
/// to the socket path instead.
pub const PIPE_NAME: &str = nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;
