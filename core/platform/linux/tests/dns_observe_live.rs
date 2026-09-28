//! One live test against the real mechanism: a resolution systemd-resolved
//! performs must reach the observer.
//!
//! Ignored by default: it needs root (the query-monitor socket is `0600`, owned
//! by systemd-resolve) and a running systemd-resolved. Run it with `--ignored`
//! on a host that has both; without them it fails with the reason.
//!
//! The query is made through `resolvectl` on purpose: on a machine whose
//! `/etc/resolv.conf` bypasses resolved (WSL, and any host with
//! `resolv.conf mode: foreign`) an ordinary lookup never reaches the monitor,
//! and the test would be measuring the machine's configuration rather than this
//! code.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]

use std::process::Command;
use std::time::{Duration, Instant};

use nrr_platform_api::dns_observe::DnsObservationSource;
use nrr_platform_linux::dns_observe::ResolvedDnsObserver;

const NAME: &str = "example.com";

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        })
        .is_some_and(|uid| uid == "0")
}

#[test]
#[ignore = "needs root and a running systemd-resolved; run with --ignored"]
fn a_resolution_through_resolved_reaches_the_observer() {
    assert!(is_root(), "the query monitor socket needs root");
    let observer = ResolvedDnsObserver::start()
        .expect("systemd-resolved's query monitor is unavailable on this host");
    // The monitor attaches asynchronously; a query sent before it is listening
    // would be missed and the test would blame the parser.
    std::thread::sleep(Duration::from_millis(500));

    let queried = Command::new("resolvectl")
        .args(["query", NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        queried,
        "the machine could not resolve {NAME} through resolvectl"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        seen.extend(observer.drain());
        if seen.iter().any(|o| o.hostname == NAME) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let observation = seen
        .iter()
        .find(|o| o.hostname == NAME)
        .unwrap_or_else(|| panic!("the resolution was not observed; saw {seen:?}"));
    assert!(
        !observation.ipv4s.is_empty(),
        "an observation must carry the addresses it learnt",
    );
}
