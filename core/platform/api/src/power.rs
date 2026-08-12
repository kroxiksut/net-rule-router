//! OS power-transition observer — the neutral port.
//!
//! Suspend/resume is the one topology change the network-change observer cannot
//! report: the machine is not running while it happens, and the OS notifications
//! that fired during sleep are gone by the time we are scheduled again. A laptop
//! therefore wakes with a stale binding — the tunnel adapter it slept with may be
//! gone, renamed, or re-created under a new identity — and nothing re-drives the
//! route table until some later event happens to arrive.
//!
//! The decision (what a resume means, how long to coalesce, what to re-drive)
//! stays neutral in `service-runtime`; only the OS mechanism lives behind this
//! trait: on Windows the SCM control handler (`SERVICE_CONTROL_POWEREVENT`), on
//! Linux logind's `PrepareForSleep`, on macOS the `NSWorkspace` sleep/wake
//! notifications. Every backend `impl`s the SAME port.
//!
//! The callback runs on an OS thread and must do the MINIMUM — it pokes a
//! debounced trigger owned by the caller.

use std::sync::Arc;

use crate::error::PlatformError;

/// A power transition worth reacting to. Deliberately coarse: the product only
/// distinguishes "we are about to stop running" from "we are running again".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerEvent {
    /// The machine is going to sleep / hibernate.
    Suspend,
    /// The machine is running again after a sleep / hibernate.
    Resume,
}

/// Invoked once per OS power transition (the caller debounces).
pub type PowerEventCallback = Arc<dyn Fn(PowerEvent) + Send + Sync>;

/// Opaque handle keeping an active subscription alive. Dropping it cancels the
/// underlying OS registration.
pub struct PowerEventSubscription {
    /// Drop guard; `()` for the no-op observer. Boxed as `dyn` so the trait's
    /// return type does not leak the per-OS representation.
    _guard: Box<dyn Send + Sync>,
}

impl PowerEventSubscription {
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

/// Observes OS suspend/resume transitions. Returns a subscription whose drop
/// cancels the registration; `Err` when the OS registration fails (the caller
/// then relies on the neutral wall-clock-gap fallback, which is never removed).
pub trait PowerEventObserver: Send + Sync {
    fn subscribe(
        &self,
        on_event: PowerEventCallback,
    ) -> Result<PowerEventSubscription, PlatformError>;
}

/// No-op observer for platforms without an impl and for tests. Subscribing
/// succeeds and nothing ever fires, so the caller falls back entirely to the
/// neutral gap detector.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPowerEventObserver;

impl PowerEventObserver for NoopPowerEventObserver {
    fn subscribe(
        &self,
        _on_event: PowerEventCallback,
    ) -> Result<PowerEventSubscription, PlatformError> {
        Ok(PowerEventSubscription::inert())
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
        let sub = NoopPowerEventObserver
            .subscribe(Arc::new(move |_| {
                f.fetch_add(1, Ordering::SeqCst);
            }))
            .expect("noop subscribe never fails");
        drop(sub);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
