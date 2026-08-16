//! OS network-topology change observer — the Windows mechanism backend.
//!
//! The neutral [`NetworkChangeObserver`] port + `NoopNetworkChangeObserver` live
//! in `nrr-platform-api`; this module holds only the Windows implementation
//! ([`WindowsNetworkChangeObserver`], via `NotifyIpInterfaceChange` +
//! `NotifyRouteChange2`). The port + its types are re-exported below so existing
//! `nrr_platform_windows::network_change::*` paths keep resolving unchanged.
//!
//! The callback runs on a Win32 worker thread and does the MINIMUM (it pokes a
//! debounced trigger owned by the caller); coalescing lives in the neutral layer.

#![allow(unsafe_code)]

// The neutral port + OS-agnostic no-op live in `nrr-platform-api`.
// Re-export them so consumers (`service-runtime`) keep importing from here.
pub use nrr_platform_api::network_change::{
    NetworkChangeCallback, NetworkChangeObserver, NetworkChangeSubscription,
    NoopNetworkChangeObserver,
};

// ── Windows impl (NotifyIpInterfaceChange + NotifyRouteChange2) ────────────────

#[cfg(target_os = "windows")]
use std::ffi::c_void;

#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{HANDLE, NO_ERROR};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, NotifyIpInterfaceChange, NotifyRouteChange2, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
};
#[cfg(target_os = "windows")]
use windows::Win32::Networking::WinSock::AF_UNSPEC;

#[cfg(target_os = "windows")]
use crate::error::PlatformError;

/// Heap context handed to the OS as the callback's caller-context. Kept alive by
/// the subscription guard and freed ONLY after both notifications are cancelled
/// (see [`WindowsSubscriptionGuard::drop`]), so no in-flight callback can ever
/// dereference a freed pointer.
#[cfg(target_os = "windows")]
struct ObserverContext {
    on_change: NetworkChangeCallback,
}

/// Common body for both change callbacks: read the context and poke the caller.
///
/// # Safety
/// `context` must be the live `*mut ObserverContext` passed to the `Notify*`
/// call (non-null, still alive because the notification has not been cancelled).
#[cfg(target_os = "windows")]
unsafe fn fire(context: *const c_void) {
    if context.is_null() {
        return;
    }
    // SAFETY: per the contract above, `context` points at the live
    // `ObserverContext` we registered; it outlives every callback because it is
    // freed only after `CancelMibChangeNotify2` makes callbacks quiescent.
    let ctx = &*(context as *const ObserverContext);
    // A panic must NEVER unwind across the `extern "system"` FFI boundary (UB).
    // The poke only locks + notifies, but guard defensively.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        (ctx.on_change)();
    }));
}

/// `NotifyIpInterfaceChange` callback. The row/type are ignored — any interface
/// change is a signal to re-evaluate routing.
#[cfg(target_os = "windows")]
unsafe extern "system" fn interface_change_callback(
    caller_context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    fire(caller_context);
}

/// `NotifyRouteChange2` callback. Catches a secondary adapter silently changing/withdrawing
/// its default route without a link-state transition.
#[cfg(target_os = "windows")]
unsafe extern "system" fn route_change_callback(
    caller_context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    fire(caller_context);
}

/// Drop guard for a live Windows subscription. Cancels BOTH notifications, then
/// frees the context — order is load-bearing (free-before-cancel is a
/// use-after-free, since `CancelMibChangeNotify2` is what guarantees no callback
/// is still running).
#[cfg(target_os = "windows")]
struct WindowsSubscriptionGuard {
    interface_handle: HANDLE,
    route_handle: HANDLE,
    context: *mut ObserverContext,
}

// SAFETY: the raw fields are only touched on `Drop` (single-threaded teardown).
// `CancelMibChangeNotify2` blocks until in-flight callbacks return, after which
// the context is exclusively owned here and safe to free. The callbacks
// themselves only read through the pointer.
#[cfg(target_os = "windows")]
unsafe impl Send for WindowsSubscriptionGuard {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WindowsSubscriptionGuard {}

#[cfg(target_os = "windows")]
impl Drop for WindowsSubscriptionGuard {
    fn drop(&mut self) {
        // SAFETY: cancel both notifications first; each `CancelMibChangeNotify2`
        // blocks until any running callback for that handle has returned, so
        // afterwards no callback can dereference `context`. THEN reclaim the Box.
        unsafe {
            if !self.interface_handle.is_invalid() {
                let _ = CancelMibChangeNotify2(self.interface_handle);
            }
            if !self.route_handle.is_invalid() {
                let _ = CancelMibChangeNotify2(self.route_handle);
            }
            if !self.context.is_null() {
                drop(Box::from_raw(self.context));
            }
        }
    }
}

/// Production observer: registers `NotifyIpInterfaceChange` (link up/down, IP
/// add/remove) and `NotifyRouteChange2` (default-route add/remove) so a secondary adapter
/// coming up or dropping re-drives routing within ~debounce, not ~1–30 s.
#[cfg(target_os = "windows")]
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsNetworkChangeObserver;

#[cfg(target_os = "windows")]
impl NetworkChangeObserver for WindowsNetworkChangeObserver {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        // Leak the context to a raw pointer; ownership moves into the guard,
        // which frees it on drop (after cancelling the notifications).
        let context = Box::into_raw(Box::new(ObserverContext { on_change }));
        let mut interface_handle = HANDLE::default();
        let mut route_handle = HANDLE::default();

        // SAFETY: `context` is a live, non-null Box pointer kept alive in the
        // returned guard until after cancellation; `interface_change_callback`
        // is a valid `extern "system"` fn matching the expected signature;
        // `&mut interface_handle` is a valid out-pointer on this frame.
        // `false` = no synchronous initial notification.
        let iface_status = unsafe {
            NotifyIpInterfaceChange(
                AF_UNSPEC,
                Some(interface_change_callback),
                Some(context as *const c_void),
                false,
                &mut interface_handle,
            )
        };
        if iface_status != NO_ERROR {
            // SAFETY: no notification was registered against `context`, so it is
            // exclusively owned here; reclaim it.
            unsafe { drop(Box::from_raw(context)) };
            return Err(PlatformError::Win32 {
                operation: "NotifyIpInterfaceChange",
                code: iface_status.0,
                message: format!("NotifyIpInterfaceChange → Win32 error {}", iface_status.0),
            });
        }

        // SAFETY: same context/callback/out-pointer validity as above.
        let route_status = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_change_callback),
                context as *const c_void,
                false,
                &mut route_handle,
            )
        };
        if route_status != NO_ERROR {
            // SAFETY: the interface notification IS live against `context`;
            // cancel it first (quiesces callbacks) THEN free the context.
            unsafe {
                let _ = CancelMibChangeNotify2(interface_handle);
                drop(Box::from_raw(context));
            }
            return Err(PlatformError::Win32 {
                operation: "NotifyRouteChange2",
                code: route_status.0,
                message: format!("NotifyRouteChange2 → Win32 error {}", route_status.0),
            });
        }

        Ok(NetworkChangeSubscription::new(Box::new(
            WindowsSubscriptionGuard {
                interface_handle,
                route_handle,
                context,
            },
        )))
    }
}
