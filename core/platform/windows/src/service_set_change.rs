//! Windows mechanism behind [`ServiceSetChangeObserver`]: the Service Control
//! Manager's create/delete notifications.
//!
//! A notification is one-shot and arrives as an APC on the thread that asked
//! for it, so one thread per subscription parks in an alertable wait and
//! registers again after each event: no timer, no wakeup while nothing changes.

#![cfg(target_os = "windows")]
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::JoinHandle;

use nrr_platform_api::error::PlatformError;
use nrr_platform_api::network_change::{NetworkChangeCallback, NetworkChangeSubscription};
use nrr_platform_api::service_set_change::ServiceSetChangeObserver;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::System::Services::{
    CloseServiceHandle, NotifyServiceStatusChangeW, OpenSCManagerW, SC_HANDLE,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_NOTIFY_2W, SERVICE_NOTIFY_CREATED,
    SERVICE_NOTIFY_DELETED, SERVICE_NOTIFY_STATUS_CHANGE_2,
};
use windows::Win32::System::Threading::{QueueUserAPC, SleepEx, INFINITE};

/// Production observer over the Service Control Manager.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsServiceSetChangeObserver;

impl ServiceSetChangeObserver for WindowsServiceSetChangeObserver {
    fn subscribe(
        &self,
        on_change: NetworkChangeCallback,
    ) -> Result<NetworkChangeSubscription, PlatformError> {
        Ok(NetworkChangeSubscription::new(Box::new(ScmWatch::start(
            on_change,
        )?)))
    }
}

/// Owns the watch thread; dropping it retires the thread.
struct ScmWatch {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ScmWatch {
    fn start(on_change: NetworkChangeCallback) -> Result<Self, PlatformError> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("nrr-service-set-watch".to_string())
            .spawn(move || watch_until_stopped(&thread_stop, &on_change, &ready_tx))
            .map_err(|e| PlatformError::Transient {
                operation: "service_set_change.spawn",
                detail: e.to_string(),
            })?;
        // The registration belongs to the thread; its verdict reaches the
        // caller instead of leaving a silent thread.
        let verdict = ready_rx.recv().unwrap_or_else(|_| {
            Err(PlatformError::Transient {
                operation: "service_set_change.register",
                detail: "the watch thread exited before registering".to_string(),
            })
        });
        match verdict {
            Ok(()) => Ok(Self {
                stop,
                thread: Some(thread),
            }),
            Err(e) => {
                let _ = thread.join();
                Err(e)
            }
        }
    }
}

/// An APC that does nothing: queued to end the alertable wait.
unsafe extern "system" fn wake(_parameter: usize) {}

impl Drop for ScmWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            // SAFETY: the handle belongs to the thread, not yet joined; the
            // routine takes no data.
            unsafe {
                QueueUserAPC(Some(wake), HANDLE(thread.as_raw_handle()), 0);
            }
            let _ = thread.join();
        }
    }
}

/// What the notification's callback reaches: set once it has run.
struct Fired(AtomicBool);

/// The SCM queues this on the registering thread, inside its alertable wait.
unsafe extern "system" fn on_notify(parameter: *const c_void) {
    // SAFETY: `parameter` is the notification buffer registered below, alive
    // until the handle is closed; its context is the `Fired` of the same frame.
    let buffer = unsafe { &*parameter.cast::<SERVICE_NOTIFY_2W>() };
    // SAFETY: as above.
    let fired = unsafe { &*buffer.pContext.cast::<Fired>() };
    fired.0.store(true, Ordering::Release);
}

fn win32(operation: &'static str, code: u32) -> PlatformError {
    PlatformError::Win32 {
        operation,
        code,
        message: format!("{operation} -> Win32 error {code}"),
    }
}

fn watch_until_stopped(
    stop: &AtomicBool,
    on_change: &NetworkChangeCallback,
    ready: &mpsc::SyncSender<Result<(), PlatformError>>,
) {
    // SAFETY: local machine, default database; closed at the end.
    let opened =
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) };
    let scm: SC_HANDLE = match opened {
        Ok(handle) => handle,
        Err(e) => {
            let _ = ready.send(Err(win32("OpenSCManagerW", e.code().0 as u32)));
            return;
        }
    };
    let fired = Fired(AtomicBool::new(false));
    // Outlives every registration: the SCM may write into it until the handle
    // is closed at the end.
    let mut notify: SERVICE_NOTIFY_2W;
    let mut first = true;
    loop {
        fired.0.store(false, Ordering::Release);
        notify = SERVICE_NOTIFY_2W {
            dwVersion: SERVICE_NOTIFY_STATUS_CHANGE_2,
            pfnNotifyCallback: Some(on_notify),
            pContext: std::ptr::addr_of!(fired).cast_mut().cast(),
            ..SERVICE_NOTIFY_2W::default()
        };
        // SAFETY: `scm` is open; `notify` and `fired` live until after the
        // handle is closed.
        let rc = unsafe {
            NotifyServiceStatusChangeW(
                scm,
                SERVICE_NOTIFY_CREATED | SERVICE_NOTIFY_DELETED,
                std::ptr::addr_of!(notify),
            )
        };
        if rc != 0 {
            if first {
                let _ = ready.send(Err(win32("NotifyServiceStatusChangeW", rc)));
            } else {
                tracing::warn!(
                    target: "nrr::override",
                    msg_key = "service-set-watch-stopped",
                    code = rc,
                    "the watch on installed services stopped; they are re-checked on a timer",
                );
            }
            break;
        }
        if first {
            let _ = ready.send(Ok(()));
            first = false;
        }
        while !fired.0.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
            // SAFETY: an alertable wait; the callback runs inside it.
            unsafe { SleepEx(INFINITE, true) };
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !notify.pszServiceNames.is_null() {
            // SAFETY: the SCM allocated the names for us to free with LocalFree.
            unsafe { LocalFree(HLOCAL(notify.pszServiceNames.0.cast())) };
        }
        on_change();
    }
    // SAFETY: closes the handle opened above, ending any pending notification.
    let _ = unsafe { CloseServiceHandle(scm) };
}
