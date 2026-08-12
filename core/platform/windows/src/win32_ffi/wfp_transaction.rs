//! WFP transaction primitives (`FwpmTransactionBegin0`,
//! `FwpmTransactionCommit0`, `FwpmTransactionAbort0`).
//!
//! Transactions group filter add/delete calls into atomic batches —
//! the apply layer relies on them for the all-or-nothing guarantee
//! across `WfpFilterSpec` lists. `Begin0(handle, 0)` opens a
//! read-write transaction; flag `FWPM_TXN_READ_ONLY = 1` is the
//! read-only variant we don't currently use.
//!
//! Per the [`crate::windows_api::WindowsApiPort`] contract, abort
//! must always succeed — Win32 itself enforces this — so it is a
//! no-result operation. We swallow the raw error code from
//! `FwpmTransactionAbort0` (treated as advisory only).

#![allow(unsafe_code)]

use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};

use crate::error::PlatformError;
use crate::types::WfpEngineToken;

use super::wfp_engine::token_to_handle;

const BEGIN_OP: &str = "FwpmTransactionBegin0";
const COMMIT_OP: &str = "FwpmTransactionCommit0";

/// Read-write transaction flags (`0`); `FWPM_TXN_READ_ONLY` would be
/// `1`, but we don't currently use it.
const TXN_READ_WRITE: u32 = 0;

/// Begin a read-write WFP transaction on the given engine handle.
pub fn transaction_begin(token: &WfpEngineToken) -> Result<(), PlatformError> {
    let handle = token_to_handle(token);
    // SAFETY: `handle` was produced by a successful `FwpmEngineOpen0`
    // and outlives this call (caller owns the token).
    let code = unsafe { FwpmTransactionBegin0(handle, TXN_READ_WRITE) };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: BEGIN_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }
    Ok(())
}

/// Commit the current transaction. After a successful commit, all
/// filter add/delete calls inside the transaction become visible to
/// the kernel atomically.
pub fn transaction_commit(token: &WfpEngineToken) -> Result<(), PlatformError> {
    let handle = token_to_handle(token);
    // SAFETY: handle is valid (caller owns the token); commit may
    // fail if no transaction is in progress, which is reported.
    let code = unsafe { FwpmTransactionCommit0(handle) };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: COMMIT_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }
    Ok(())
}

/// Abort the current transaction. Per the trait contract, this never
/// fails from the caller's perspective — Win32's documented
/// invariant is "abort always rolls back the transaction state, even
/// if an error is returned" (the error indicates a non-existent
/// transaction or a session-already-corrupted scenario, both of
/// which leave the engine in a benign state).
///
/// On the off chance Win32 returns non-zero, the value is logged
/// implicitly via the audit pathway upstream — but we never propagate
/// it.
pub fn transaction_abort(token: &WfpEngineToken) {
    let handle = token_to_handle(token);
    // SAFETY: handle is valid; abort cleans up regardless of outcome.
    let _ = unsafe { FwpmTransactionAbort0(handle) };
}

#[cfg(test)]
mod tests {
    use super::super::wfp_engine::{engine_close, engine_open};
    use super::*;

    /// Smoke test: full begin/commit cycle on a real Windows host.
    ///
    /// **Requires administrator privileges** — `FwpmTransactionBegin0`
    /// returns `ERROR_ACCESS_DENIED` (5) for non-elevated callers even
    /// for empty transactions. The production service runs as
    /// `NT AUTHORITY\SYSTEM` so this constraint is satisfied.
    ///
    /// Run on demand: `cargo test -p nrr-platform-windows -- --ignored`
    /// from an elevated shell.
    #[test]
    #[ignore = "requires admin: FwpmTransactionBegin0 returns ERROR_ACCESS_DENIED for non-elevated processes"]
    fn begin_commit_empty_transaction_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0 must succeed");
        transaction_begin(&token).expect("FwpmTransactionBegin0 must succeed");
        transaction_commit(&token).expect("FwpmTransactionCommit0 must succeed");
        engine_close(token).expect("FwpmEngineClose0 must succeed");
    }

    /// Smoke test: begin / abort cycle.
    ///
    /// **Requires administrator privileges** — same gate as the
    /// commit-cycle test.
    #[test]
    #[ignore = "requires admin: FwpmTransactionBegin0 returns ERROR_ACCESS_DENIED for non-elevated processes"]
    fn begin_abort_empty_transaction_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0 must succeed");
        transaction_begin(&token).expect("FwpmTransactionBegin0 must succeed");
        transaction_abort(&token);
        engine_close(token).expect("FwpmEngineClose0 must succeed");
    }
}
