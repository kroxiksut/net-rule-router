//! SCM service-status probe.
//!
//! Lets the client distinguish four cases when the named pipe isn't
//! responding:
//!
//! - **NotFound** — service is not installed (no SCM entry). Pipe will
//!   never come up unless the user installs.
//! - **Stopped** — service exists but is not running. Pipe comes up when
//!   user / SCM starts the service.
//! - **StartPending / StopPending** — transitional. We back off briefly
//!   and retry without dropping into `NotInstalled`.
//! - **Running** — pipe should accept us; if connect still fails, it's
//!   a transient transport issue.
//!
//! Production calls `OpenSCManagerW(SC_MANAGER_CONNECT)` then
//! `OpenServiceW(svc, SERVICE_QUERY_STATUS)` then `QueryServiceStatusEx`.
//! All three calls are read-only and don't require admin.

#![allow(unsafe_code)]

use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING,
};

/// Result of a single SCM probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceProbe {
    /// Service is not installed.
    NotFound,
    /// Service exists but is stopped.
    Stopped,
    /// Service is starting up.
    StartPending,
    /// Service is shutting down.
    StopPending,
    /// Service is running.
    Running,
    /// SCM call failed for some other reason. Treat as transient.
    Unknown { code: u32 },
}

/// Service name registered in SCM. Taken from the product-identity source of
/// truth rather than mirrored by hand: this crate must not depend on the
/// service runtime, and a second literal would drift the moment the service is
/// renamed.
const SERVICE_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_NAME;

/// Run an SCM status query for the NetRuleRouter service. Always returns
/// some `ServiceProbe`; never panics.
pub fn probe() -> ServiceProbe {
    // Step 1: connect to SCM (read-only).
    let scm = match open_scm_for_query() {
        Ok(h) => h,
        Err(code) => return ServiceProbe::Unknown { code },
    };
    let _scm_guard = ScHandleGuard(scm);

    // Step 2: open the service entry.
    let svc = match open_service_for_query(scm) {
        OpenSvcResult::Ok(h) => h,
        OpenSvcResult::NotFound => return ServiceProbe::NotFound,
        OpenSvcResult::OtherError(code) => return ServiceProbe::Unknown { code },
    };
    let _svc_guard = ScHandleGuard(svc);

    // Step 3: query status.
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes_needed = 0u32;
    // SAFETY: `status` is a POD struct on stack; size is the buffer
    // capacity; bytes_needed is a stack out-pointer. svc is a valid
    // handle owned by the guard.
    let result = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            Some(std::slice::from_raw_parts_mut(
                &mut status as *mut _ as *mut u8,
                std::mem::size_of::<SERVICE_STATUS_PROCESS>(),
            )),
            &mut bytes_needed as *mut u32,
        )
    };
    if result.is_err() {
        let code = result.err().map(|e| e.code().0 as u32).unwrap_or(0);
        return ServiceProbe::Unknown { code };
    }

    match status.dwCurrentState {
        SERVICE_RUNNING => ServiceProbe::Running,
        SERVICE_STOPPED => ServiceProbe::Stopped,
        SERVICE_START_PENDING => ServiceProbe::StartPending,
        SERVICE_STOP_PENDING => ServiceProbe::StopPending,
        other => ServiceProbe::Unknown { code: other.0 },
    }
}

/// Open SCM for read-only queries. No admin needed.
fn open_scm_for_query() -> Result<SC_HANDLE, u32> {
    // SAFETY: passing nulls for machine name and database name targets
    // local SCM with the default database; access flag is read-only.
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|e| e.code().0 as u32)
}

enum OpenSvcResult {
    Ok(SC_HANDLE),
    NotFound,
    OtherError(u32),
}

fn open_service_for_query(scm: SC_HANDLE) -> OpenSvcResult {
    let wide: Vec<u16> = SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: scm is a valid SCM handle; wide is null-terminated; access
    // flag SERVICE_QUERY_STATUS is read-only and doesn't require admin.
    let result = unsafe { OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_STATUS) };
    match result {
        Ok(h) => OpenSvcResult::Ok(h),
        Err(e) => {
            let code = e.code().0 as u32;
            // ERROR_SERVICE_DOES_NOT_EXIST = 1060
            if code == 1060 {
                OpenSvcResult::NotFound
            } else {
                OpenSvcResult::OtherError(code)
            }
        }
    }
}

/// RAII closer for SC_HANDLE.
struct ScHandleGuard(SC_HANDLE);

impl Drop for ScHandleGuard {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle came from OpenSCManagerW or OpenServiceW;
            // matching close is CloseServiceHandle.
            unsafe {
                let _ = windows::Win32::System::Services::CloseServiceHandle(self.0);
            }
            self.0 = SC_HANDLE::default();
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_returns_some_variant() {
        // On a CI machine without the service installed we expect
        // `NotFound`. On a developer box with the service installed, any
        // of the other variants is valid. Either way the call must
        // return without panicking.
        let r = probe();
        let _ = r;
    }

    #[test]
    fn service_probe_variants_distinct_in_match() {
        // Sanity that match exhaustiveness for every variant compiles.
        let variants = [
            ServiceProbe::NotFound,
            ServiceProbe::Stopped,
            ServiceProbe::StartPending,
            ServiceProbe::StopPending,
            ServiceProbe::Running,
            ServiceProbe::Unknown { code: 0 },
        ];
        for v in variants {
            let _: &str = match v {
                ServiceProbe::NotFound => "not-found",
                ServiceProbe::Stopped => "stopped",
                ServiceProbe::StartPending => "start-pending",
                ServiceProbe::StopPending => "stop-pending",
                ServiceProbe::Running => "running",
                ServiceProbe::Unknown { .. } => "unknown",
            };
        }
    }
}
