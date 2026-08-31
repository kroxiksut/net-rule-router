//! Windows implementation of the interactive-logon port.
//!
//! A service has no window, so `WM_WTSSESSION_CHANGE` never reaches it — the OS
//! delivers session transitions to the SCM control handler instead. That handler
//! is registered before any runtime dependency exists, so the callback is parked
//! in a process-wide slot the handler dispatches into; the service runs one SCM
//! connection per process, so there is exactly one producer.

use std::sync::{Arc, Mutex, OnceLock};

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::logon_session::{
    LogonSessionCallback, LogonSessionEvent, LogonSessionObserver, LogonSessionSubscription,
};
use windows_service::service::{SessionChangeParam, SessionChangeReason};

fn slot() -> &'static Mutex<Option<LogonSessionCallback>> {
    static SLOT: OnceLock<Mutex<Option<LogonSessionCallback>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Maps an SCM session-change reason onto the coarse port event, or `None` for
/// the ones that say nothing about whether a principal is present: lock/unlock
/// keeps the same signed-in user, and the session-create/terminate and
/// remote-control edges carry no logon of their own.
fn classify(reason: SessionChangeReason) -> Option<LogonSessionEvent> {
    match reason {
        // `SessionLogon` is the sign-in itself; the connect edges cover the case
        // where a session that already existed becomes the attached one.
        SessionChangeReason::SessionLogon
        | SessionChangeReason::ConsoleConnect
        | SessionChangeReason::RemoteConnect => Some(LogonSessionEvent::SignedIn),
        SessionChangeReason::SessionLogoff
        | SessionChangeReason::ConsoleDisconnect
        | SessionChangeReason::RemoteDisconnect => Some(LogonSessionEvent::SignedOut),
        _ => None,
    }
}

/// Called from the SCM control handler for every `SERVICE_CONTROL_SESSIONCHANGE`.
/// Unwraps the SCM parameter and hands the reason on; the session id is not
/// consulted — "somebody is signed in" is the whole question, and the routing
/// layer resolves WHO on its own.
pub fn dispatch(param: SessionChangeParam) {
    dispatch_reason(param.reason);
}

/// The dispatch itself, taking only what it uses — so it is reachable from a
/// test without constructing an FFI notification struct.
fn dispatch_reason(reason: SessionChangeReason) {
    let Some(event) = classify(reason) else {
        return;
    };
    let callback = slot()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .map(Arc::clone);
    if let Some(callback) = callback {
        callback(event);
    }
}

/// Clears the parked callback when the subscription is dropped, so a control
/// event arriving during teardown finds nothing to call.
struct SlotGuard;

impl Drop for SlotGuard {
    fn drop(&mut self) {
        *slot().lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// The SCM-backed observer. Under console mode nothing ever dispatches into it;
/// the periodic re-arm covers that case.
#[derive(Debug, Default, Clone, Copy)]
pub struct ScmLogonSessionObserver;

impl LogonSessionObserver for ScmLogonSessionObserver {
    fn subscribe(
        &self,
        on_event: LogonSessionCallback,
    ) -> Result<LogonSessionSubscription, PlatformError> {
        *slot().lock().unwrap_or_else(|p| p.into_inner()) = Some(on_event);
        Ok(LogonSessionSubscription::new(Box::new(SlotGuard)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn lock_and_unlock_are_not_logon_transitions() {
        assert_eq!(classify(SessionChangeReason::SessionLock), None);
        assert_eq!(classify(SessionChangeReason::SessionUnlock), None);
    }

    #[test]
    fn logon_dispatches_and_unsubscribing_stops_it() {
        let signed_in = Arc::new(AtomicUsize::new(0));
        let s = Arc::clone(&signed_in);
        let sub = ScmLogonSessionObserver
            .subscribe(Arc::new(move |event| {
                if event == LogonSessionEvent::SignedIn {
                    s.fetch_add(1, Ordering::SeqCst);
                }
            }))
            .expect("subscribe never fails");

        dispatch_reason(SessionChangeReason::SessionLogon);
        dispatch_reason(SessionChangeReason::SessionLock);
        dispatch_reason(SessionChangeReason::SessionLogoff);
        assert_eq!(signed_in.load(Ordering::SeqCst), 1);

        drop(sub);
        dispatch_reason(SessionChangeReason::SessionLogon);
        assert_eq!(signed_in.load(Ordering::SeqCst), 1);
    }
}
