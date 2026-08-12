//! WFP engine open/close (`FwpmEngineOpen0`, `FwpmEngineClose0`).
//!
//! Lifecycle pattern (per `core/platform/windows/src/wfp/mod.rs`):
//! one engine handle is opened at the start of an apply, used for the
//! entire transaction, and closed when the apply completes. The handle
//! is opaque outside this module — we wrap the raw `HANDLE` in
//! `WfpEngineToken { raw: u64 }`.
//!
//! ## Authentication mode
//!
//! `RPC_C_AUTHN_WINNT` (value `10`) — standard Windows NTLM/Kerberos
//! authentication, the only mode supported by FWPM. Service-side
//! callers run as `NT AUTHORITY\SYSTEM`, so the engine session is
//! always elevated; the apply layer relies on this contract for
//! `FwpmFilterAdd0` to succeed.

#![allow(unsafe_code)]

use std::ffi::c_void;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use crate::error::PlatformError;
use crate::types::WfpEngineToken;

const OPEN_OP: &str = "FwpmEngineOpen0";
const CLOSE_OP: &str = "FwpmEngineClose0";

/// Open a WFP engine session.
///
/// **Non-dynamic** (the `session` arg is `None` = default flags): filters added
/// in this session are NOT auto-removed when the engine handle closes — they
/// persist until an explicit delete or a reboot. Cleanup is therefore explicit
/// (see `wfp::WfpSession` / `PerSidApplyOrchestrator::cleanup_wfp`).
///
/// The returned [`WfpEngineToken`] must eventually be passed to
/// [`engine_close`] — leaking it leaves an FWP session attached to the
/// process until termination.
pub fn engine_open() -> Result<WfpEngineToken, PlatformError> {
    let mut handle = HANDLE::default();
    // SAFETY: `FwpmEngineOpen0` writes a valid HANDLE into `handle` on
    // success; on error the handle stays default. `RPC_C_AUTHN_WINNT`
    // is a documented constant. `PCWSTR::null()` for `servername`
    // selects the local machine. `None` for `authidentity` and
    // `session` selects defaults (current process token, default
    // session flags).
    let code = unsafe {
        FwpmEngineOpen0(
            PCWSTR(std::ptr::null()),
            RPC_C_AUTHN_WINNT,
            None,
            None,
            &mut handle,
        )
    };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: OPEN_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }
    Ok(WfpEngineToken {
        raw: handle.0 as usize as u64,
    })
}

/// Close a previously opened WFP engine session. The token is
/// consumed by value to make double-close at the type level
/// impossible.
pub fn engine_close(token: WfpEngineToken) -> Result<(), PlatformError> {
    let handle = token_to_handle(&token);
    // SAFETY: `handle` was returned by a successful `FwpmEngineOpen0`
    // and is consumed by-value here, so the same token cannot reach
    // `FwpmEngineClose0` twice via this safe API.
    let code = unsafe { FwpmEngineClose0(handle) };
    if code != 0 {
        return Err(PlatformError::Win32 {
            operation: CLOSE_OP,
            code,
            message: format!("Win32 error 0x{code:08X}"),
        });
    }
    Ok(())
}

/// Reconstruct a `HANDLE` from a [`WfpEngineToken`]. The raw `u64`
/// always fits — it was produced by widening a `*mut c_void` we own.
pub(super) fn token_to_handle(token: &WfpEngineToken) -> HANDLE {
    HANDLE(token.raw as usize as *mut c_void)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity round-trip: `token.raw` survives a HANDLE↔u64 conversion.
    #[test]
    fn token_handle_roundtrip_preserves_value() {
        let probe: usize = 0xDEAD_BEEF;
        let token = WfpEngineToken { raw: probe as u64 };
        let h = token_to_handle(&token);
        assert_eq!(h.0 as usize, probe);
    }

    /// Smoke test: open / close on a real Windows host. Requires only
    /// the privileges to talk to the Base Filtering Engine — every
    /// process has them; we don't need admin rights for `Open0`/
    /// `Close0` themselves (filter add/delete is the elevated step).
    #[test]
    fn open_close_engine_round_trip_on_windows() {
        let token = engine_open().expect("FwpmEngineOpen0 must succeed");
        // Smoke value: handle is non-null after a successful open.
        assert_ne!(token.raw, 0, "valid engine handle is non-null");
        engine_close(token).expect("FwpmEngineClose0 must succeed");
    }
}
