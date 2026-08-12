//! Wire-format IPC payload types — re-export shim.
//!
//! The canonical definitions moved into [`nrr_shared::ipc_payloads`] so
//! that `nrr-ipc-client` can build typed requests without crossing the
//! forbidden `nrr-ipc-client → nrr-service-runtime` dependency
//! boundary. Existing handler code that imports
//! `super::payloads::*` keeps working unchanged.

pub use nrr_shared::ipc_payloads::*;
