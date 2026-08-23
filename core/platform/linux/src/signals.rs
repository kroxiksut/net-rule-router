//! Graceful-stop signals for the daemon: `SIGTERM` (systemd stop) and
//! `SIGINT` (Ctrl+C in a console run).
//!
//! The Linux analog of the Windows service's SCM stop control. It exists for
//! one reason: the daemon's teardown removes the packet filters and the routes
//! this product installed, and a process killed by the default disposition of
//! `SIGTERM` never runs it. What is left behind is a machine still enforcing a
//! policy no service maintains — a leak-guard `drop` with nothing to lift it.
//!
//! ## Why a flag and a watcher thread, not the callback itself
//!
//! Almost nothing may run inside a signal handler: it interrupts an arbitrary
//! thread mid-instruction, so allocating, locking, or logging there can
//! deadlock the process it is trying to stop. The handler therefore does the
//! one thing that is async-signal-safe — a store into a lock-free atomic — and
//! an ordinary thread notices and calls the stop callback.
//!
//! `SA_RESTART` is set deliberately: the daemon's netlink readers block in
//! `recv`, and without it the stop signal would surface to them as `EINTR`
//! errors on the way out.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use nrr_platform_api::error::PlatformError;

/// How often the watcher thread looks at the flag. Fast enough that a stop
/// feels immediate, cheap enough to be invisible.
const POLL: Duration = Duration::from_millis(100);

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The handler. Its whole contract is the store below.
extern "C" fn on_stop_signal(_signum: libc::c_int) {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Whether a stop signal has been delivered.
#[must_use]
pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

/// Install the handlers and start the watcher that calls `on_stop` once.
///
/// The callback runs on an ordinary thread, so it may do real work — request
/// the stop token, log, whatever the caller needs.
pub fn install_stop_signals<F>(on_stop: F) -> Result<(), PlatformError>
where
    F: Fn() + Send + 'static,
{
    install_handler(libc::SIGTERM)?;
    install_handler(libc::SIGINT)?;

    std::thread::Builder::new()
        .name("nrr-stop-signal".to_owned())
        .spawn(move || {
            while !stop_requested() {
                std::thread::sleep(POLL);
            }
            on_stop();
        })
        .map_err(|e| PlatformError::Transient {
            operation: "spawn stop-signal watcher",
            detail: e.to_string(),
        })?;
    Ok(())
}

fn install_handler(signum: libc::c_int) -> Result<(), PlatformError> {
    // SAFETY: `sigaction` is initialised to zero and then filled in full; the
    // handler is an `extern "C"` fn with the required signature, and the call
    // itself only reads the struct we pass.
    let rc = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_stop_signal as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask));
        libc::sigaction(signum, std::ptr::addr_of!(action), std::ptr::null_mut())
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        return Err(PlatformError::Errno {
            operation: "sigaction",
            code: e.raw_os_error().unwrap_or(0),
            message: e.to_string(),
        });
    }
    Ok(())
}
