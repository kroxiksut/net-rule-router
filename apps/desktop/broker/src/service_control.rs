//! Start a `SERVICE_DEMAND_START` service from the unprivileged launcher.
//!
//! When the service is configured `SERVICE_DEMAND_START` (start on app launch),
//! the interactive console user holds a targeted `SERVICE_START` grant on the
//! service object (added by the elevated `set-start-mode demand` subcommand).
//! That lets the non-elevated launcher start the service with NO UAC prompt.
//! For a `SERVICE_AUTO_START` service (no grant), `OpenServiceW` with
//! `SERVICE_START` fails with access-denied — which is precisely the signal to
//! skip and fall back to the mock backend.
//!
//! All `unsafe` lives here so the launcher stays unsafe-free.

#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, StartServiceW, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOPPED,
};

/// OS service name, taken from the product-identity source of truth. The broker
/// must not depend on `nrr-service-runtime` (dependency direction:
/// `apps/broker → nrr-ipc-client + nrr-shared`), and the contracts crate is
/// exactly where a name both of them need belongs.
const SERVICE_NAME: &str = nrr_shared::product_identity::WINDOWS_SERVICE_NAME;

/// Total time to wait for a freshly-started service to reach `RUNNING` before
/// returning to the caller (which then re-probes IPC on its own cadence).
const START_WAIT: Duration = Duration::from_secs(6);
/// Poll cadence while waiting for `RUNNING`.
const POLL: Duration = Duration::from_millis(150);

/// Result of [`try_start_demand_service`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandStartOutcome {
    /// The service was stopped and a start was requested (and observed, or the
    /// wait timed out while still start-pending).
    Started,
    /// The service was already running / start-pending — nothing to do.
    AlreadyRunning,
    /// Could not act: service not installed, this user lacks `SERVICE_START`
    /// (i.e. not a DemandStart-with-grant service), or it is mid-transition.
    /// The caller falls back to the mock backend.
    NotStartable,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// RAII wrapper so every early return closes the handle exactly once.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: opened by Open{SCManager,Service}W; closed exactly once.
            let _ = unsafe { CloseServiceHandle(self.0) };
        }
    }
}

/// Best-effort: start the service if this user is allowed to (the DemandStart
/// grant) and it is currently stopped. Never prompts for UAC and never panics —
/// every failure path returns [`DemandStartOutcome::NotStartable`].
pub fn try_start_demand_service() -> DemandStartOutcome {
    // SAFETY: local active SCM database; `SC_MANAGER_CONNECT` is the minimum to
    // open a named service.
    let Ok(scm) = (unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) })
    else {
        return DemandStartOutcome::NotStartable;
    };
    let scm = ScHandle(scm);
    let name = to_wide(SERVICE_NAME);
    // SAFETY: `scm` valid; `name` NUL-terminated. Access-denied here means no
    // SERVICE_START grant (an AutoStart service) → NotStartable.
    let Ok(svc) = (unsafe {
        OpenServiceW(
            scm.0,
            PCWSTR(name.as_ptr()),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    }) else {
        return DemandStartOutcome::NotStartable;
    };
    let svc = ScHandle(svc);

    let mut status = SERVICE_STATUS::default();
    // SAFETY: `svc` valid; `status` is a valid out-param.
    if unsafe { QueryServiceStatus(svc.0, &mut status) }.is_err() {
        return DemandStartOutcome::NotStartable;
    }
    if status.dwCurrentState == SERVICE_RUNNING || status.dwCurrentState == SERVICE_START_PENDING {
        return DemandStartOutcome::AlreadyRunning;
    }
    if status.dwCurrentState != SERVICE_STOPPED {
        // Stop-pending / paused — don't fight a transition we didn't start.
        return DemandStartOutcome::NotStartable;
    }
    // SAFETY: `svc` opened with SERVICE_START; no argument vectors.
    if unsafe { StartServiceW(svc.0, None) }.is_err() {
        return DemandStartOutcome::NotStartable;
    }
    // Wait for RUNNING so the caller's IPC re-probe lands on an accepting pipe.
    let deadline = Instant::now() + START_WAIT;
    loop {
        std::thread::sleep(POLL);
        let mut s = SERVICE_STATUS::default();
        // SAFETY: `svc` valid; out-param valid.
        if unsafe { QueryServiceStatus(svc.0, &mut s) }.is_ok()
            && s.dwCurrentState == SERVICE_RUNNING
        {
            return DemandStartOutcome::Started;
        }
        if Instant::now() >= deadline {
            // Requested but not yet RUNNING — still report Started; the caller's
            // IPC connect has its own retry/backoff.
            return DemandStartOutcome::Started;
        }
    }
}
