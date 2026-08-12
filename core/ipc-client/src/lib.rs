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
//! ## Crate boundaries (CLAUDE.md)
//!
//! Allowed: `nrr-shared`, `nrr-application`.
//!
//! Forbidden: `nrr-service-runtime`, `nrr-windows-service`,
//! `nrr-platform-windows`, `nrr-storage`, `nrr-diagnostics`, any UI crate,
//! `nrr-mock-backend`. The client must round-trip through the wire
//! protocol only — no shortcut into service internals.

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
pub mod wire;
pub mod wire_error;

#[cfg(target_os = "windows")]
mod transport;

/// Unix `AF_UNIX` transport primitive. Public so it is a discoverable
/// building block for the Unix client; the Windows `transport` stays
/// private because only `client` consumes it.
#[cfg(unix)]
pub mod transport_unix;

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

#[cfg(target_os = "windows")]
pub mod backend_facade_impl;

#[cfg(target_os = "windows")]
pub use backend_facade_impl::{ipc_operation_timeout, IpcBackendFacade};
#[cfg(target_os = "windows")]
pub use client::NamedPipeIpcClient;
pub use connection::{ConnectionStatus, IpcClient, IpcClientError, NegotiateInfo};
pub use wire::{read_frame, write_frame, WireError};
pub use wire_error::ipc_error_to_wire;

/// Canonical Windows pipe path for the `service-v1` protocol. Derived from
/// the cross-OS endpoint SSOT in `nrr-shared::ipc_transport` so the client,
/// the service, and the (future) Unix socket path never drift. Consumed only
/// by the `#[cfg(target_os = "windows")]` transport; on Unix the SSOT resolves
/// to the socket path instead.
pub const PIPE_NAME: &str = nrr_shared::ipc_transport::SERVICE_ENDPOINT_ADDRESS;
