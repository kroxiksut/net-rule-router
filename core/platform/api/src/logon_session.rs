//! Interactive-logon observer — the neutral port.
//!
//! Policy is per-principal: until someone is signed in there is no SID, hence
//! no rules to apply. Anything that enforces on a user's behalf has to wait for
//! one, and the wait must be event-driven — the sign-in happens inside the
//! logon phase, and a service that polls either arms too early (into the middle
//! of that phase, where the OS is resolving names and a DNS interception costs
//! the user seconds of a frozen logon screen) or too late.
//!
//! The decision — what a sign-in means and what to re-drive — stays neutral in
//! `service-runtime`; only the OS mechanism lives behind this trait: on Windows
//! the SCM control handler (`SERVICE_CONTROL_SESSIONCHANGE`), on Linux logind,
//! on macOS the `NSWorkspace` session notifications. Every backend `impl`s the
//! SAME port.
//!
//! The callback runs on an OS thread and must do the MINIMUM — it pokes a
//! debounced trigger owned by the caller.

use std::sync::Arc;

use crate::error::PlatformError;

/// A logon transition worth reacting to. Deliberately coarse: the product only
/// distinguishes "someone is now present" from "they are gone". Lock/unlock is
/// neither — the SID stays valid across a locked screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonSessionEvent {
    /// An interactive user signed in (console or remote).
    SignedIn,
    /// An interactive user signed out.
    SignedOut,
}

/// Invoked once per OS logon transition (the caller debounces).
pub type LogonSessionCallback = Arc<dyn Fn(LogonSessionEvent) + Send + Sync>;

/// Opaque handle keeping an active subscription alive. Dropping it cancels the
/// underlying OS registration.
pub struct LogonSessionSubscription {
    /// Drop guard; `()` for the no-op observer. Boxed as `dyn` so the trait's
    /// return type does not leak the per-OS representation.
    _guard: Box<dyn Send + Sync>,
}

impl LogonSessionSubscription {
    /// Wrap a per-OS drop guard (its `Drop` cancels the OS registration).
    pub fn new(guard: Box<dyn Send + Sync>) -> Self {
        Self { _guard: guard }
    }

    /// A subscription that owns nothing (the no-op observer).
    pub fn inert() -> Self {
        Self {
            _guard: Box::new(()),
        }
    }
}

/// Observes interactive sign-in / sign-out. Returns a subscription whose drop
/// cancels the registration; `Err` when the OS registration fails (the caller
/// then relies on its periodic re-arm, which is never removed).
pub trait LogonSessionObserver: Send + Sync {
    fn subscribe(
        &self,
        on_event: LogonSessionCallback,
    ) -> Result<LogonSessionSubscription, PlatformError>;
}

/// No-op observer for platforms without an impl and for tests. Subscribing
/// succeeds and nothing ever fires, so the caller falls back entirely to its
/// periodic re-arm.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopLogonSessionObserver;

impl LogonSessionObserver for NoopLogonSessionObserver {
    fn subscribe(
        &self,
        _on_event: LogonSessionCallback,
    ) -> Result<LogonSessionSubscription, PlatformError> {
        Ok(LogonSessionSubscription::inert())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn noop_subscribe_returns_inert_and_never_fires() {
        let fired = Arc::new(AtomicUsize::new(0));
        let f = Arc::clone(&fired);
        let sub = NoopLogonSessionObserver
            .subscribe(Arc::new(move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            }))
            .expect("noop subscribe never fails");
        drop(sub);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
