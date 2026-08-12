//! OS network-topology change observer — the neutral port.
//!
//! The service subscribes a callback that fires whenever the OS reports an
//! interface / route change, so the routing + kill-switch layer can re-evaluate
//! IMMEDIATELY (sub-100 ms) instead of waiting for the 1 s adapter poll or the
//! 30 s safety tick. The decision + coalescing logic stays neutral in
//! `service-runtime`; only the OS mechanism (Win32 `NotifyIpInterfaceChange` /
//! `NotifyRouteChange2`; Linux rtnetlink; macOS `NWPathMonitor`) lives behind
//! this trait, so every backend `impl`s the SAME port.
//!
//! The callback runs on an OS worker thread and does the MINIMUM (it pokes a
//! debounced trigger owned by the caller); coalescing lives in the neutral layer
//! so it is unit-testable without a live OS.

use std::sync::Arc;

use crate::error::PlatformError;

/// A callback invoked (raw, once per OS change — the caller debounces) whenever
/// the OS reports a network-topology change.
pub type NetworkChangeCallback = Arc<dyn Fn() + Send + Sync>;

/// Opaque handle keeping an active subscription alive. Dropping it cancels the
/// underlying OS notification (and, on Windows, waits for any in-flight callback
/// to complete before freeing the shared context — no use-after-free).
pub struct NetworkChangeSubscription {
    /// Drop guard. `()` for the no-op observer; a backend boxes a guard whose
    /// `Drop` cancels the OS notification (and frees any callback context) —
    /// boxed as `dyn` so the trait's return type does not leak the per-OS
    /// representation.
    _guard: Box<dyn Send + Sync>,
}

impl NetworkChangeSubscription {
    /// Wrap a per-OS drop guard (its `Drop` cancels the OS notification). Public
    /// so a backend crate can construct the subscription it returns.
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

/// Observes OS network-topology changes and invokes `on_change` (coalescing is
/// the caller's job). Returns a [`NetworkChangeSubscription`] whose drop cancels
/// the notification; `Err` when the OS registration fails (the caller then keeps
/// relying on the polling fallback, which is never removed).
pub trait NetworkChangeObserver: Send + Sync {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError>;
}

/// No-op observer for platforms without an impl, tests, and the recovery-blocked
/// path. `subscribe` succeeds and returns an inert subscription; no events ever
/// fire, so the caller falls back entirely to polling.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNetworkChangeObserver;

impl NetworkChangeObserver for NoopNetworkChangeObserver {
    fn subscribe(
        &self,
        _on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Ok(NetworkChangeSubscription::inert())
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
        let observer = NoopNetworkChangeObserver;
        let sub = observer
            .subscribe(Arc::new(move || {
                f.fetch_add(1, Ordering::SeqCst);
            }))
            .expect("noop subscribe never fails");
        // Inert: dropping is clean and the callback was never invoked.
        drop(sub);
        assert_eq!(fired.load(Ordering::SeqCst), 0);
    }
}
