//! Diagnostic probe — do the fail-closed kill-switch filter specs
//! actually materialize in WFP on this host?
//!
//! The production apply path is best-effort: a filter spec that
//! `FwpmFilterAdd0` rejects is silently skipped, and the skip identities
//! are only visible at debug verbosity. That can let the fail-closed
//! posture appear armed in the service log while traffic still egresses
//! over the primary link. This probe reproduces the exact filter specs
//! the orchestrator emits and drives each one through the real
//! `FwpmFilterAdd0`, recording the per-filter outcome.
//!
//! ## Safety: nothing is ever committed
//!
//! Every add runs inside a WFP transaction that is **always aborted** —
//! `FwpmFilterAdd0` validates and returns its error synchronously, so the
//! probe observes materialization results while the abort guarantees no
//! filter ever takes effect. Network traffic is not touched. (The idempotent
//! sub-layer registration performed by `add_filter` is rolled back with the
//! same abort.)
//!
//! ## Running
//!
//! Requires elevation (`FwpmEngineOpen0`/`FwpmTransactionBegin0` demand an
//! admin token), hence `#[ignore]` like the other admin-gated WFP tests:
//!
//! ```text
//! cargo test -p nrr-service-runtime --test wfp_fail_closed_probe -- --ignored --nocapture
//! ```
//!
//! A failing filter is reported with its layer/action/conditions, the raw
//! `PlatformError` rendering, and whether the production best-effort apply
//! would have silently skipped it (`is_unmaterializable_filter`).
#![allow(clippy::expect_used)]
#![cfg(windows)]

use std::net::Ipv4Addr;

use nrr_platform_api::types::WfpFilterSpec;
use nrr_platform_windows::win32_ffi::wfp_engine::engine_open;
use nrr_platform_windows::win32_ffi::wfp_filter::add_filter;
use nrr_platform_windows::win32_ffi::wfp_transaction::{transaction_abort, transaction_begin};
use nrr_service_runtime::killswitch_codegen::{
    fail_closed_block_all_filters, fail_closed_block_destinations, kill_switch_filters,
    FailClosedExemptions, KillSwitchProtocols,
};

/// Any well-formed SID exercises the `FWPM_CONDITION_ALE_USER_ID` SDDL path;
/// materialization does not depend on which principal it names. BUILTIN\Users
/// keeps the probe host-agnostic.
const PROBE_SID: &str = "S-1-5-32-545";

/// Exemption shape: one connected LAN subnet, one
/// known VPN bootstrap server, strict DNS posture (`allow_dns_over_primary`
/// disabled). Documentation-range addresses (RFC 5737) so the
/// specs are host-agnostic.
fn probe_exemptions() -> FailClosedExemptions {
    FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(203, 0, 113, 10)],
        local_subnets: vec![(Ipv4Addr::new(192, 168, 0, 0), 24)],
        primary_dest_ips: Vec::new(),
        allow_dns_over_primary: false,
        known_direct_ips: Vec::new(),
        // Liveness-probe target (tunnel next-hop) — private-range like the
        // real derived next-hop it stands in for.
        probe_target_ips: vec![Ipv4Addr::new(10, 91, 192, 1)],
    }
}

/// Drive every spec through the real `FwpmFilterAdd0` inside one transaction,
/// abort the transaction, and return the failures as `(spec, error text,
/// would-best-effort-skip)` triples. Panics only on environment errors
/// (engine/transaction), never on per-filter outcomes.
fn probe_specs(label: &str, specs: &[WfpFilterSpec]) -> Vec<(WfpFilterSpec, String, bool)> {
    assert!(
        !specs.is_empty(),
        "{label}: codegen returned no specs — probe precondition broken"
    );
    let token = engine_open().expect("FwpmEngineOpen0 — run from an ELEVATED shell");
    transaction_begin(&token).expect("FwpmTransactionBegin0 — run from an ELEVATED shell");
    let mut failures = Vec::new();
    for spec in specs {
        match add_filter(&token, spec) {
            Ok(_) => println!(
                "OK    [{label}] {:?} {:?} id={:016x} w={:#x} ip={:?} subnet={:?} v6={:?} port={:?} proto={:?} sid={} luid={:?}",
                spec.layer,
                spec.action,
                spec.id.raw,
                spec.weight,
                spec.remote_ip,
                spec.remote_subnet,
                spec.remote_subnet_v6,
                spec.remote_port,
                spec.ip_protocol,
                spec.user_sid.is_some(),
                spec.local_interface_luid,
            ),
            Err(e) => {
                let skip = e.is_unmaterializable_filter();
                println!(
                    "FAIL  [{label}] {:?} {:?} id={:016x} w={:#x} ip={:?} subnet={:?} v6={:?} port={:?} proto={:?} sid={} luid={:?} best_effort_would_skip={skip} err={e}",
                    spec.layer,
                    spec.action,
                    spec.id.raw,
                    spec.weight,
                    spec.remote_ip,
                    spec.remote_subnet,
                    spec.remote_subnet_v6,
                    spec.remote_port,
                    spec.ip_protocol,
                    spec.user_sid.is_some(),
                    spec.local_interface_luid,
                );
                failures.push((spec.clone(), e.to_string(), skip));
            }
        }
    }
    transaction_abort(&token);
    println!(
        "SUMMARY [{label}]: {} spec(s), {} failed, transaction ABORTED (nothing committed)",
        specs.len(),
        failures.len()
    );
    failures
}

/// The catch-all fail-closed set (`block_all` /
/// `FailClosedUnknown` escalation, all protocols selected — exactly what the
/// service arms while the secondary is unresolved). Fails listing every
/// spec `FwpmFilterAdd0` rejects; passes only if the whole set materializes.
#[test]
#[ignore = "requires admin: FwpmEngineOpen0/FwpmTransactionBegin0/FwpmFilterAdd0 need elevation"]
fn probe_catch_all_fail_closed_filters_materialize_on_windows() {
    let specs =
        fail_closed_block_all_filters(PROBE_SID, &probe_exemptions(), KillSwitchProtocols::ALL);
    let failures = probe_specs("catch-all", &specs);
    assert!(
        failures.is_empty(),
        "{} of {} catch-all fail-closed filter(s) failed to materialize: {:#?}",
        failures.len(),
        specs.len(),
        failures
            .iter()
            .map(|(s, e, skip)| format!(
                "{:?}/{:?} id={:016x} proto={:?} best_effort_would_skip={skip}: {e}",
                s.layer, s.action, s.id.raw, s.ip_protocol
            ))
            .collect::<Vec<_>>()
    );
}

/// The historic per-IP path (mode A with the secondary unresolved): ALE block
/// plus packet-layer mirrors per pinned destination. This is what runs on
/// every normal apply, so if its packet-layer half is rejected it also
/// explains the constant `skipped=19` in the apply summaries.
#[test]
#[ignore = "requires admin: FwpmEngineOpen0/FwpmTransactionBegin0/FwpmFilterAdd0 need elevation"]
fn probe_per_destination_fail_closed_filters_materialize_on_windows() {
    let protected = [
        Ipv4Addr::new(198, 51, 100, 7),
        Ipv4Addr::new(203, 0, 113, 44),
    ];
    let specs = fail_closed_block_destinations(PROBE_SID, &protected, KillSwitchProtocols::ALL);
    let failures = probe_specs("per-dest", &specs);
    assert!(
        failures.is_empty(),
        "{} of {} per-destination fail-closed filter(s) failed to materialize: {:#?}",
        failures.len(),
        specs.len(),
        failures
            .iter()
            .map(|(s, e, skip)| format!(
                "{:?}/{:?} id={:016x} proto={:?} best_effort_would_skip={skip}: {e}",
                s.layer, s.action, s.id.raw, s.ip_protocol
            ))
            .collect::<Vec<_>>()
    );
}

/// The remaining condition kinds in one pass: the leak-proof pair
/// (`IP_LOCAL_INTERFACE` LUID-conditioned egress permits over blocks, at both
/// ALE and packet layers) and the DNS-over-primary relaxation
/// (`IP_REMOTE_PORT` 53 exempts). The LUID value does not have to name a live
/// adapter — `FwpmFilterAdd0` validates the condition shape, not the
/// interface's existence.
#[test]
#[ignore = "requires admin: FwpmEngineOpen0/FwpmTransactionBegin0/FwpmFilterAdd0 need elevation"]
fn probe_leak_proof_pair_and_dns_exempt_filters_materialize_on_windows() {
    let mut specs = kill_switch_filters(
        PROBE_SID,
        &[Ipv4Addr::new(198, 51, 100, 7)],
        0x0011_2233_4455_6677,
        KillSwitchProtocols::ALL,
    );
    let dns_exemptions = FailClosedExemptions {
        allow_dns_over_primary: true,
        ..probe_exemptions()
    };
    specs.extend(fail_closed_block_all_filters(
        PROBE_SID,
        &dns_exemptions,
        KillSwitchProtocols::ALL,
    ));
    let failures = probe_specs("pair+dns", &specs);
    assert!(
        failures.is_empty(),
        "{} of {} leak-proof-pair / DNS-exempt filter(s) failed to materialize: {:#?}",
        failures.len(),
        specs.len(),
        failures
            .iter()
            .map(|(s, e, skip)| format!(
                "{:?}/{:?} id={:016x} proto={:?} port={:?} luid={:?} best_effort_would_skip={skip}: {e}",
                s.layer, s.action, s.id.raw, s.ip_protocol, s.remote_port, s.local_interface_luid
            ))
            .collect::<Vec<_>>()
    );
}
