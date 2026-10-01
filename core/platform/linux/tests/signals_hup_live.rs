//! A hang-up from the terminal of a foreground run must reach the stop
//! callback, or the daemon dies on the default disposition and its filters,
//! routes and resolver redirect stay behind.
//!
//! A test binary of its own: the stop flag is process-wide, so beside the
//! `SIGTERM` test it could not tell which signal set it.

#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::time::Duration;

#[test]
fn a_sighup_reaches_the_stop_callback() {
    let (tx, rx) = mpsc::channel();
    nrr_platform_linux::signals::install_stop_signals(move || {
        let _ = tx.send(());
    })
    .expect("install stop signals");
    assert!(!nrr_platform_linux::signals::stop_requested());

    // SAFETY: raising a signal in our own process; the handler installed above
    // is the one that receives it.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::raise(libc::SIGHUP) };
    assert_eq!(rc, 0, "raise(SIGHUP) failed");

    rx.recv_timeout(Duration::from_secs(5))
        .expect("the stop callback did not run — a closed SSH session would kill the daemon");
    assert!(nrr_platform_linux::signals::stop_requested());
}
