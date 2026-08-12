//! Cursor-based pagination — re-export shim.
//!
//! The canonical definition lives in [`nrr_shared::pagination`] so the
//! IPC client crate can build typed paginated requests without
//! depending on `nrr-diagnostics`. Original consumers continue to
//! import from `nrr_diagnostics::facade::pagination::*`; the shim
//! preserves those import paths.

pub use nrr_shared::pagination::*;
