//! One live test against the real mechanism: a delivered `SIGTERM` must reach
//! the stop callback. Needs no root and no systemd — the process signals
//! itself — so it runs anywhere the daemon can.

#![cfg(target_os = "linux")]

use std::sync::mpsc;
use std::time::Duration;

#[test]
fn a_sigterm_reaches_the_stop_callback() {
    let (tx, rx) = mpsc::channel();
    nrr_platform_linux::signals::install_stop_signals(move || {
        let _ = tx.send(());
    })
    .expect("install stop signals");

    // SAFETY: raising a signal in our own process; the handler installed above
    // is the one that receives it.
    #[allow(unsafe_code)]
    let rc = unsafe { libc::raise(libc::SIGTERM) };
    assert_eq!(rc, 0, "raise(SIGTERM) failed");

    rx.recv_timeout(Duration::from_secs(5))
        .expect("the stop callback did not run — a systemd stop would kill the daemon instead");
    assert!(nrr_platform_linux::signals::stop_requested());
}
