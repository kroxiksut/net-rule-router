//! Containment for callbacks the OS calls on its own threads.
//!
//! A panic cannot unwind out of an `extern "system"` function: Rust aborts the
//! process there, past the service's teardown, so one indexing slip in an event
//! decoder would take the whole service down with the system DNS still pointed
//! at its resolver. Each callback body runs here instead and loses only the one
//! event it was handling.

use std::sync::atomic::{AtomicU64, Ordering};

static CONTAINED: AtomicU64 = AtomicU64::new(0);

/// Runs `body`, swallowing a panic. Logged on the 1st, 2nd, 4th, 8th... one, so
/// a decoder that panics on every event cannot flood the log.
pub(crate) fn contain_panic(source: &'static str, body: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).is_ok() {
        return;
    }
    let count = CONTAINED.fetch_add(1, Ordering::Relaxed) + 1;
    if count.is_power_of_two() {
        tracing::error!(
            target: "nrr::platform::callback",
            source,
            count,
            "an OS callback panicked; the event was dropped and the service goes on",
        );
    }
}

// The test needs an `extern "system"` function to call, as the OS would.
#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// Shaped like the real callbacks: an `extern "system"` function whose body
    /// panics. Without containment the test binary aborts.
    unsafe extern "system" fn panicking_callback(_context: *mut std::ffi::c_void) {
        contain_panic("test", || panic!("simulated decoder panic"));
    }

    #[test]
    fn a_panicking_os_callback_returns_instead_of_aborting_the_process() {
        let before = CONTAINED.load(Ordering::Relaxed);
        // SAFETY: the callback ignores its argument.
        unsafe { panicking_callback(std::ptr::null_mut()) };
        assert!(CONTAINED.load(Ordering::Relaxed) > before);
    }
}
