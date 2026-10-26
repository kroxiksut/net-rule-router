//! The block that holds a signed-in person between a reboot and the service's
//! first pass.
//!
//! Our filters live as long as the engine, so a reboot takes them; the service
//! starts with no filter at all, and the first pass over a signed-in user comes
//! seconds after sign-in, while autostart programs already connect. With
//! "everything through the tunnel" on, the machine going down leaves one
//! persistent block per family for the INTERACTIVE group. The first pass over
//! somebody present removes it as an unclaimed filter of ours; every teardown
//! does too.

#![cfg(target_os = "windows")]

use crate::error::PlatformError;
use crate::win32_ffi::{wfp_engine, wfp_filter, wfp_transaction};

/// Put the boot guard in the engine, in one transaction. Already there counts
/// as done.
pub fn install() -> Result<(), PlatformError> {
    let token = wfp_engine::engine_open()?;
    let outcome = add_in_transaction(&token);
    let _ = wfp_engine::engine_close(token);
    outcome
}

fn add_in_transaction(token: &crate::types::WfpEngineToken) -> Result<(), PlatformError> {
    wfp_transaction::transaction_begin(token)?;
    if let Err(e) = wfp_filter::add_boot_guard(token) {
        wfp_transaction::transaction_abort(token);
        return Err(e);
    }
    wfp_transaction::transaction_commit(token)
}
