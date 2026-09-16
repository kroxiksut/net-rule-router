//! One test against the LIVE route table, per the rule every platform port
//! here follows: fixtures prove the shape, but only the kernel proves the
//! mechanism.
//!
//! The unit tests in `route_table` cover the encoder and the dump parser
//! against byte fixtures on any host. What they cannot cover is whether the
//! kernel accepts what we encode — a wrong attribute or a mis-set flag reads
//! perfectly in a fixture and is rejected, or worse silently ignored, by
//! rtnetlink. So this adds a route on the loopback interface, finds it in a
//! real dump, deletes it, and checks it is gone.
//!
//! Skips itself, loudly, when the host cannot run it (no root). A skipped run
//! prints why: a test that silently passes on an unequipped machine is worse
//! than no test, because it reads as coverage.
//!
//! The destination sits in TEST-NET-3 (RFC 5737, reserved for documentation)
//! and the host part carries the pid, so a run cannot collide with real traffic
//! or with a parallel run. The IPv6 twin uses `2001:db8::/32` (RFC 3849) the
//! same way — and it is the only place a real `/128` meets a real kernel, since
//! no machine here has global IPv6 to test against.

#![cfg(target_os = "linux")]
// Same convention as the other integration tests here: a failed setup step in a
// test is a panic with a message, not an error to propagate.
#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nrr_platform_api::enforcement::RouteTableRef;
use nrr_platform_api::error::{ErrorClass, PlatformError};
use nrr_platform_api::route_table::RouteTablePort;
use nrr_platform_api::types::RouteEntry;
use nrr_platform_linux::LinuxApi;

fn is_root() -> bool {
    // No libc dependency needed for one number the kernel already exposes.
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

/// Loopback is index 1 on every Linux host and is always up, so the route has
/// somewhere to point without this test having to create an interface.
const LOOPBACK_IFINDEX: u32 = 1;

fn test_route() -> RouteEntry {
    // TEST-NET-3, host part from the pid: unique per run, routable nowhere.
    let pid = std::process::id();
    let destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (pid % 200 + 20) as u8));
    RouteEntry {
        destination,
        prefix_length: 32,
        // On-link: no gateway, which is also the shape that would break if the
        // encoder emitted a zero RTA_GATEWAY instead of omitting it.
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        interface_index: LOOPBACK_IFINDEX,
        metric: 4242,
        is_ours: true,
        table: RouteTableRef::Main,
    }
}

fn test_route_v6() -> RouteEntry {
    // RFC 3849 documentation prefix; host part from the pid, as in the v4 twin.
    let pid = std::process::id();
    let destination = IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0x0db8,
        0,
        0,
        0,
        0,
        0,
        (pid % 40000 + 1000) as u16,
    ));
    RouteEntry {
        destination,
        prefix_length: 128,
        next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        interface_index: LOOPBACK_IFINDEX,
        metric: 4242,
        is_ours: true,
        table: RouteTableRef::Main,
    }
}

#[test]
fn a_route_can_be_added_found_and_removed_on_a_live_kernel() {
    if !is_root() {
        eprintln!(
            "SKIPPED a_route_can_be_added_found_and_removed_on_a_live_kernel: \
             needs root — the kernel refuses route mutations from an unprivileged caller"
        );
        return;
    }

    let api = LinuxApi;
    let route = test_route();

    // Leftovers from a killed previous run would make the add fail with
    // EEXIST; deleting first is harmless when there is nothing there.
    let _ = api.delete_ip_forward_entry(&route);

    api.create_ip_forward_entry(&route)
        .expect("the kernel must accept the route we encode");

    let table = api
        .get_ip_forward_table()
        .expect("dumping the route table needs no privilege");
    let found = table
        .iter()
        .find(|r| r.destination == route.destination && r.prefix_length == 32)
        .expect("the route we just added must appear in the dump");
    assert_eq!(
        found.interface_index, LOOPBACK_IFINDEX,
        "the route must be attached to the interface we asked for"
    );
    assert_eq!(
        found.metric, route.metric,
        "the metric must survive the round trip — it is what orders competing routes"
    );
    assert!(
        found.next_hop.is_unspecified(),
        "an on-link route must come back without a gateway"
    );

    api.delete_ip_forward_entry(&route)
        .expect("the kernel must accept the delete");

    let after = api.get_ip_forward_table().expect("dump after delete");
    assert!(
        !after
            .iter()
            .any(|r| r.destination == route.destination && r.prefix_length == 32),
        "the route must be gone after the delete"
    );
}

/// The IPv6 host route (`/128`), against the same live kernel.
///
/// The v4 test proves the encoder's shape; it cannot prove the v6 one, because
/// the family changes the rtmsg family byte, the RTA_DST width and the dump we
/// have to recognise it in. Everything below the neutral plan is per-family
/// mechanism, so it needs its own contact with the kernel.
#[test]
fn a_v6_host_route_can_be_added_found_and_removed_on_a_live_kernel() {
    if !is_root() {
        eprintln!(
            "SKIPPED a_v6_host_route_can_be_added_found_and_removed_on_a_live_kernel: \
             needs root — the kernel refuses route mutations from an unprivileged caller"
        );
        return;
    }

    let api = LinuxApi;
    let route = test_route_v6();

    let _ = api.delete_ip_forward_entry(&route);

    api.create_ip_forward_entry(&route)
        .expect("the kernel must accept the /128 we encode");

    let table = api
        .get_ip_forward_table()
        .expect("dumping the route table needs no privilege");
    let found = table
        .iter()
        .find(|r| r.destination == route.destination && r.prefix_length == 128)
        .expect(
            "the /128 we just added must appear in the dump — an AF_INET-only dump would miss it",
        );
    assert_eq!(
        found.interface_index, LOOPBACK_IFINDEX,
        "the route must be attached to the interface we asked for"
    );
    assert!(
        found.next_hop.is_unspecified(),
        "an on-link route must come back without a gateway — the only shape a \
         tunnel without a v6 address of its own can offer"
    );
    assert!(
        matches!(found.next_hop, IpAddr::V6(_)),
        "an IPv6 route must not come back carrying a v4 next hop"
    );

    api.delete_ip_forward_entry(&route)
        .expect("the kernel must accept the delete");

    let after = api.get_ip_forward_table().expect("dump after delete");
    assert!(
        !after
            .iter()
            .any(|r| r.destination == route.destination && r.prefix_length == 128),
        "the /128 must be gone after the delete"
    );
}

/// A route whose destination and next hop disagree on family is refused before
/// it reaches the kernel: rtnetlink would answer a bare EINVAL, which says
/// nothing about which of our own two fields is wrong.
#[test]
fn a_route_mixing_families_is_refused_before_the_kernel_sees_it() {
    let api = LinuxApi;
    let mut route = test_route_v6();
    route.next_hop = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    let err = api
        .create_ip_forward_entry(&route)
        .expect_err("a mixed-family route must not be encodable");
    assert!(
        format!("{err:?}").contains("different address families"),
        "the error must name the actual defect, got {err:?}"
    );
}

/// Deleting what is not there must classify as idempotent, not as a failure:
/// the reconcile loop deletes routes it believes it owns, and a route the user
/// already removed by hand must not abort the pass.
#[test]
fn deleting_an_absent_route_is_idempotent() {
    if !is_root() {
        eprintln!(
            "SKIPPED deleting_an_absent_route_is_idempotent: \
             needs root — the kernel refuses route mutations from an unprivileged caller"
        );
        return;
    }

    let api = LinuxApi;
    let mut route = test_route();
    // A different host part, never added by this run.
    route.destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 251));

    match api.delete_ip_forward_entry(&route) {
        Ok(()) => panic!("deleting a route that was never added must not report success"),
        Err(e) => {
            assert_eq!(
                e.classify(),
                ErrorClass::Idempotent,
                "a missing route must read as idempotent, got {e}"
            );
            assert!(
                matches!(e, PlatformError::Errno { .. }),
                "the kernel's own errno must survive to the caller, got {e}"
            );
        }
    }
}

/// Adding the same route twice must classify as a conflict rather than a
/// generic failure — the apply layer treats `Conflict` on add as "already in
/// the state we wanted".
#[test]
fn adding_the_same_route_twice_is_a_conflict() {
    if !is_root() {
        eprintln!(
            "SKIPPED adding_the_same_route_twice_is_a_conflict: \
             needs root — the kernel refuses route mutations from an unprivileged caller"
        );
        return;
    }

    let api = LinuxApi;
    let mut route = test_route();
    route.destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 252));
    let _ = api.delete_ip_forward_entry(&route);

    api.create_ip_forward_entry(&route).expect("first add");
    let second = api.create_ip_forward_entry(&route);
    let _ = api.delete_ip_forward_entry(&route);

    match second {
        Ok(()) => panic!("the second add must not report success — NLM_F_EXCL asked otherwise"),
        Err(e) => assert_eq!(
            e.classify(),
            ErrorClass::Conflict,
            "a duplicate route must read as a conflict, got {e}"
        ),
    }
}
