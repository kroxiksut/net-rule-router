//! One live test against the real mechanism: a link appearing must reach the
//! subscriber, because that is the event a tunnel coming up produces and the
//! whole point of the observer is not waiting out the timer for it.
//!
//! Needs root (`ip link add`) — without it, a loud SKIP rather than a pass.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nrr_platform_api::network_change::NetworkChangeObserver;
use nrr_platform_linux::network_change::LinuxNetworkChangeObserver;

/// Interface name used only by this test. Distinct from anything a real machine
/// carries, so a failed cleanup is obvious rather than confusing.
const LINK: &str = "nrrlive0";

fn ip(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn a_link_appearing_reaches_the_subscriber() {
    if !nix_is_root() {
        eprintln!(
            "SKIPPED: not root — `ip link add` needs it. Run as root to exercise the netlink \
             observer against the kernel."
        );
        return;
    }
    let _ = ip(&["link", "del", LINK]);

    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let observer = LinuxNetworkChangeObserver;
    let _subscription = observer
        .subscribe(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }))
        .expect("subscribe to netlink");

    assert!(
        ip(&["link", "add", LINK, "type", "dummy"]),
        "could not add the test link"
    );
    let _ = ip(&["link", "set", LINK, "up"]);

    let deadline = Instant::now() + Duration::from_secs(5);
    while seen.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let observed = seen.load(Ordering::SeqCst);
    let _ = ip(&["link", "del", LINK]);

    assert!(
        observed > 0,
        "the kernel's link change never reached the subscriber — a tunnel coming up would wait \
         for the timer instead",
    );
}

fn nix_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}
