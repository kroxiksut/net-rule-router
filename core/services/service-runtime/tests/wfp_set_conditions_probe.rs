//! Diagnostic probe — how many OR'd `FWPM_CONDITION_IP_REMOTE_ADDRESS`
//! conditions does this host's BFE accept in ONE filter?
//!
//! The packed kill-switch form (`nrr_platform_api::wfp_slotting`) rests on
//! WFP's documented same-field-OR semantics, but the per-filter condition
//! ceiling is undocumented. This probe drives the three packed shapes the
//! codegen emits — the ALE egress-conditional permit (the fattest: user SID +
//! interface LUID + address set), the ALE block, and the transport-layer
//! protocol-narrowed block — through the real `FwpmFilterAdd0` at escalating
//! set sizes, and REQUIRES the shipped cap
//! ([`nrr_platform_api::wfp_slotting::V4_SET_MAX_CONDITIONS`]) to materialize.
//! Larger sizes are probed informationally to show the actual headroom.
//!
//! ## Safety: nothing is ever committed
//!
//! Every add runs inside a WFP transaction that is **always aborted** —
//! `FwpmFilterAdd0` validates and returns synchronously, so materialization is
//! observable while the abort guarantees no filter ever takes effect.
//!
//! ## Running
//!
//! Requires elevation (`FwpmEngineOpen0` demands an admin token):
//!
//! ```text
//! cargo test -p nrr-service-runtime --test wfp_set_conditions_probe -- --ignored --nocapture
//! ```
#![allow(clippy::expect_used)]
#![cfg(windows)]

use std::net::Ipv4Addr;

use nrr_platform_api::types::{WfpAction, WfpFilterId, WfpFilterSpec, WfpLayerKey};
use nrr_platform_api::wfp_slotting::V4_SET_MAX_CONDITIONS;
use nrr_platform_windows::win32_ffi::wfp_engine::engine_open;
use nrr_platform_windows::win32_ffi::wfp_filter::add_filter;
use nrr_platform_windows::win32_ffi::wfp_transaction::{transaction_abort, transaction_begin};

/// BUILTIN\Users — exercises the `ALE_USER_ID` SDDL path host-agnostically.
const PROBE_SID: &str = "S-1-5-32-545";

/// Documentation-range addresses (RFC 5737 + 198.18.0.0/15 bench range for
/// the large sizes) — host-agnostic, never routed.
fn probe_ips(n: usize) -> Vec<Ipv4Addr> {
    (0..n)
        .map(|i| Ipv4Addr::new(198, 18, (i / 256) as u8, (i % 256) as u8))
        .collect()
}

struct Shape {
    label: &'static str,
    layer: WfpLayerKey,
    action: WfpAction,
    user_sid: Option<&'static str>,
    luid: Option<u64>,
    proto: Option<u8>,
}

const SHAPES: [Shape; 3] = [
    Shape {
        label: "ale-egress-permit",
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        user_sid: Some(PROBE_SID),
        luid: Some(0x0001_0000_0000_0007),
        proto: None,
    },
    Shape {
        label: "ale-block",
        layer: WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Block,
        user_sid: Some(PROBE_SID),
        luid: None,
        proto: None,
    },
    Shape {
        label: "transport-proto-block",
        layer: WfpLayerKey::OutboundTransportV4,
        action: WfpAction::Block,
        user_sid: None,
        luid: None,
        proto: Some(1), // ICMP
    },
];

fn set_spec(shape: &Shape, n: usize, id_raw: u64) -> WfpFilterSpec {
    WfpFilterSpec {
        layer: shape.layer,
        action: shape.action,
        remote_ip: None,
        remote_ip_set: probe_ips(n),
        remote_port: None,
        weight: 0x0040_0000,
        id: WfpFilterId::from_raw(id_raw),
        user_sid: shape.user_sid.map(str::to_string),
        app_pattern: None,
        local_interface_luid: shape.luid,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: shape.proto,
    }
}

#[test]
#[ignore = "needs elevation and a live BFE — diagnostic probe, run with --ignored"]
fn packed_set_cap_materializes_on_this_host() {
    let token = engine_open().expect("FwpmEngineOpen0 — run from an ELEVATED shell");
    transaction_begin(&token).expect("FwpmTransactionBegin0 — run from an ELEVATED shell");

    let sizes = [8usize, 16, 32, V4_SET_MAX_CONDITIONS, 128, 256, 512];
    let mut id_raw = 0x5E7_C0DE_0000u64;
    let mut cap_failures = Vec::new();
    for shape in &SHAPES {
        for &n in &sizes {
            id_raw += 1;
            let spec = set_spec(shape, n, id_raw);
            match add_filter(&token, &spec) {
                Ok(_) => println!("OK    [{}] {} OR'd remote-ip conditions", shape.label, n),
                Err(e) => {
                    println!(
                        "FAIL  [{}] {} OR'd remote-ip conditions: {e}",
                        shape.label, n
                    );
                    if n <= V4_SET_MAX_CONDITIONS {
                        cap_failures.push(format!("{} at {n}: {e}", shape.label));
                    }
                }
            }
        }
    }
    transaction_abort(&token);
    println!("SUMMARY: transaction ABORTED (nothing committed)");
    assert!(
        cap_failures.is_empty(),
        "the shipped cap V4_SET_MAX_CONDITIONS={V4_SET_MAX_CONDITIONS} does not materialize on \
         this host — lower it before trusting the packed codegen:\n{}",
        cap_failures.join("\n")
    );
}
