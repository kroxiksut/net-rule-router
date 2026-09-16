//! Unit tests for [`super`] — the kill-switch code generator.
//!
//! 1563 of the module's lines were this block. Moved out verbatim (one
//! level of indentation removed and nothing else) so the file one reads to
//! understand the code is the code.

/// A tunnel whose endpoint is a v6 address has to be able to reconnect
/// through the very cut that protects it. The v4 half does this with the
/// server exemption; the v6 half had nothing at all, so the block was
/// absolute and the client could not come back from any user.
#[test]
fn the_v6_cut_still_lets_the_tunnel_itself_out() {
    const LUID: u64 = 0x1234_5678;
    let out = catch_all_v6_filters("S", LUID, &[], &[]);
    for layer in [
        WfpLayerKey::AleAuthConnectV6,
        WfpLayerKey::OutboundIpPacketV6,
    ] {
        assert!(
            out.iter().any(|f| f.layer == layer
                && f.action == WfpAction::Permit
                && f.local_interface_luid == Some(LUID)),
            "{layer:?}: no egress permit through the tunnel",
        );
    }
    // An unresolved tunnel has no egress to permit - and must not turn the
    // cut into a permit-everything by accident.
    let unresolved = catch_all_v6_filters("S", 0, &[], &[]);
    assert!(unresolved.iter().all(|f| f.local_interface_luid.is_none()));
    assert!(unresolved.iter().any(|f| f.action == WfpAction::Block));
}

/// The two block-everything postures must spare the same things. The
/// catch-all (tunnel UP, everything off-tunnel dropped) used to carry a
/// smaller exemption set than the fail-closed block-all (tunnel gone), so a
/// host the user carved out onto the main link answered while the tunnel
/// was DOWN and stopped answering when it came up.
#[test]
fn the_catch_all_spares_what_its_twin_spares() {
    let direct = Ipv4Addr::new(203, 0, 113, 40);
    let primary = Ipv4Addr::new(198, 51, 100, 50);
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![Ipv4Addr::new(9, 9, 9, 9)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: Vec::new(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
        primary_dest_ips: vec![primary],
        allow_dns_over_primary: false,
        known_direct_ips: vec![direct],
        probe_target_ips: Vec::new(),
        secondary_luid: 0,
    };
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &exemptions,
        KillSwitchProtocols::ALL,
    );

    assert!(
        out.iter().any(|f| f.remote_ip == Some(direct)
            && f.action == WfpAction::Permit
            && f.layer == WfpLayerKey::AleAuthConnectV4),
        "a known-direct host must keep its connect-layer permit",
    );
    assert!(
        out.iter().any(|f| f.remote_ip == Some(primary)
            && f.action == WfpAction::Permit
            && f.layer == WfpLayerKey::OutboundTransportV4),
        "ping to a main-link host must survive the packet-layer block",
    );
}
use super::*;
// The v6 constants moved to `super::v6`; the parent no longer imports the type.
use std::net::Ipv6Addr;

/// Weight of the top rule band in [`crate::wfp_codegen`]
/// (`BASE_PRIMARY`). The kill-switch must outrank it.
const RULE_PRIMARY_BAND: u64 = 0x0020_0000;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

/// The v4 spelling most of these tests were written in. The pin set carries
/// both families now; the v6 half has tests of its own.
fn v4_pins<const N: usize>(ips: [Ipv4Addr; N]) -> Vec<IpAddr> {
    ips.into_iter().map(IpAddr::V4).collect()
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse().expect("literal"))
}

const LUID: u64 = 0x0001_0000_0000_0007;

#[test]
fn fake_ip_pool_permit_carves_both_families_above_the_block() {
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    let filters = fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), false);
    assert_eq!(
        filters.len(),
        4,
        "v4 + v6 permits plus the v4 + v6 UDP blocks for the dual-stack pool"
    );

    let v4 = &filters[0];
    assert_eq!(v4.action, WfpAction::Permit);
    assert_eq!(v4.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(v4.remote_subnet, Some((Ipv4Addr::new(198, 18, 0, 0), 15)));
    assert_eq!(v4.user_sid.as_deref(), Some("S-1-5-21-7"));
    // Above the catch-all block so the app can always reach the pool → TUN.
    assert!(v4.weight > CATCHALL_BLOCK_WEIGHT);
    // Protocol-agnostic: TCP flows into the pool must pass.
    assert_eq!(v4.ip_protocol, None);

    let v6 = &filters[1];
    assert_eq!(v6.layer, WfpLayerKey::AleAuthConnectV6);
    assert!(v6.remote_subnet_v6.is_some());
    assert_ne!(v4.weight, v6.weight, "distinct weights, no collision");
}

#[test]
fn fake_ip_pool_udp_is_blocked_by_default() {
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    let filters = fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), false);
    let udp_blocks: Vec<_> = filters
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    assert_eq!(udp_blocks.len(), 2, "one UDP block per address family");
    for block in &udp_blocks {
        assert_eq!(
            block.ip_protocol,
            Some(PROTO_UDP),
            "the block must be UDP-narrowed — TCP into the pool stays permitted"
        );
        assert_eq!(block.user_sid.as_deref(), Some("S-1-5-21-7"));
    }
    assert!(
        udp_blocks
            .iter()
            .any(|f| f.remote_subnet == Some((Ipv4Addr::new(198, 18, 0, 0), 15))),
        "the v4 block covers the whole pool subnet"
    );
    let ids: std::collections::HashSet<_> = filters.iter().map(|f| &f.id).collect();
    assert_eq!(ids.len(), filters.len(), "distinct filter ids");
}

#[test]
fn fake_ip_pool_udp_is_permitted_when_relay_enabled() {
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    let filters = fake_ip_pool_permit_filters("S-1-5-21-7", &FakeIpPoolConfig::default(), true);
    assert_eq!(
        filters.len(),
        2,
        "only the v4 + v6 permits — no UDP blocks once the relay carries UDP"
    );
    assert!(
        filters.iter().all(|f| f.action == WfpAction::Permit),
        "no Block filters when udp_relay_enabled is true"
    );
    assert!(
        filters.iter().all(|f| f.ip_protocol.is_none()),
        "the permits stay protocol-agnostic — UDP now rides the same permit as TCP"
    );
}

#[test]
fn fake_ip_pool_permit_is_v4_only_for_a_v4_only_pool() {
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    let filters = fake_ip_pool_permit_filters("S", &FakeIpPoolConfig::v4_only(), false);
    assert_eq!(filters.len(), 2, "the v4 permit plus its UDP block");
    assert!(filters.iter().all(|f| f.remote_subnet_v6.is_none()));
    assert_eq!(filters[0].action, WfpAction::Permit);
    assert_eq!(filters[1].action, WfpAction::Block);
    assert_eq!(filters[1].ip_protocol, Some(PROTO_UDP));
}

#[test]
fn fake_ip_pool_permit_is_v4_only_permit_when_relay_enabled_for_v4_only_pool() {
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    let filters = fake_ip_pool_permit_filters("S", &FakeIpPoolConfig::v4_only(), true);
    assert_eq!(filters.len(), 1, "just the v4 permit — no UDP block");
    assert_eq!(filters[0].action, WfpAction::Permit);
    assert_eq!(filters[0].ip_protocol, None);
}

#[test]
fn empty_destinations_yield_no_filters() {
    assert!(kill_switch_filters("S", &v4_pins([]), LUID, KillSwitchProtocols::ALL).is_empty());
}

#[test]
fn zero_luid_disables_kill_switch() {
    // A bad LUID must fail OPEN — never emit a black-hole Block.
    let out = kill_switch_filters(
        "S",
        &v4_pins([ip(203, 0, 113, 5)]),
        0,
        KillSwitchProtocols::ALL,
    );
    assert!(out.is_empty(), "zero LUID must produce no filters");
}

#[test]
fn single_destination_emits_ale_pair_plus_packet_pair() {
    // All protocols: 1 dest → ALE permit+block (TCP/UDP) + one packet
    // egress-permit + block per NAMED packet protocol (ICMP/IGMP/GRE/ESP;
    // 16.HW-0716: "Other" no longer adds an agnostic pair) = 2 + 4×2 = 10.
    let out = kill_switch_filters(
        "S",
        &v4_pins([ip(203, 0, 113, 5)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert_eq!(out.len(), 10);
    let permit = &out[0];
    let block = &out[1];
    assert_eq!(permit.action, WfpAction::Permit);
    assert_eq!(permit.layer, WfpLayerKey::AleAuthConnectV4);
    // Packed form: the destination lives in the OR'd set, not `remote_ip`.
    assert_eq!(permit.remote_ip, None);
    assert_eq!(permit.remote_ip_set, vec![ip(203, 0, 113, 5)]);
    assert_eq!(
        permit.local_interface_luid,
        Some(LUID),
        "ALE permit half carries the egress-interface condition"
    );
    assert_eq!(block.action, WfpAction::Block);
    assert_eq!(
        block.local_interface_luid, None,
        "ALE block is unconditional"
    );
    // The packet pair: an egress-conditional permit (carries the LUID) and
    // an unconditional packet block, both at the packet layer.
    let pkt: Vec<_> = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
        .collect();
    assert_eq!(
        pkt.len(),
        8,
        "one egress-permit + block pair per named protocol"
    );
    assert!(pkt
        .iter()
        .any(|f| f.action == WfpAction::Permit && f.local_interface_luid == Some(LUID)));
    assert!(pkt.iter().any(|f| f.action == WfpAction::Block));
    // 16.HW-0716 — every packet filter is narrowed to a named protocol;
    // the protocol-agnostic block-all is gone.
    assert!(pkt.iter().all(|f| f.ip_protocol.is_some()));
}

#[test]
fn icmp_only_emits_packet_pair_no_ale() {
    // Only ICMP: no ALE pair (no TCP/UDP), one packet egress-permit + block.
    let protos = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: true,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = kill_switch_filters("S", &v4_pins([ip(8, 8, 8, 8)]), LUID, protos);
    // No ALE pair (no TCP/UDP selected) — only the ICMP packet pair.
    assert_eq!(out.len(), 2);
    assert!(out
        .iter()
        .all(|f| f.layer == WfpLayerKey::OutboundTransportV4));
    assert!(out
        .iter()
        .any(|f| f.action == WfpAction::Block && f.ip_protocol == Some(1)));
    assert!(out.iter().any(|f| f.action == WfpAction::Permit
        && f.local_interface_luid == Some(LUID)
        && f.ip_protocol == Some(1)));
}

#[test]
fn ale_permit_outranks_ale_block_outranks_rule_band() {
    let out = kill_switch_filters(
        "S",
        &v4_pins([ip(8, 8, 8, 8)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    let permit = &out[0];
    let block = &out[1];
    assert!(permit.weight > block.weight, "permit must outrank block");
    assert!(
        block.weight > RULE_PRIMARY_BAND,
        "kill-switch block must outrank the rule primary band"
    );
}

// ── Fixtures shared by more than one theme ───────────────────────────────

fn full_resolution() -> KillSwitchResolution {
    KillSwitchResolution {
        secondary_luid: LUID,
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
    }
}

mod catch_all;
mod fail_closed;
mod ipv6;
mod per_app;
