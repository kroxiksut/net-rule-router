use super::*;

// ── Catch-all kill-switch (mode B) ──────────────────────────────────────

/// A corporate VPN the user runs beside ours keeps carrying its traffic when
/// the block-all arms. Cutting it would make the product the reason a working
/// connection died, and from the outside that is indistinguishable from the
/// corporate VPN failing on its own.
///
/// The permit is on the EGRESS interface, never on an address range: exempting
/// the tunnel's addresses would open them on the primary link too, which is
/// the leak this block-all exists to stop.
#[test]
fn a_foreign_tunnel_keeps_carrying_its_own_traffic_under_the_block_all() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0001;
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: Vec::new(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: vec![FOREIGN],
        primary_dest_ips: Vec::new(),
        allow_dns_over_primary: false,
        known_direct_ips: Vec::new(),
        probe_target_ips: Vec::new(),
        secondary_luid: LUID,
    };
    let filters =
        fail_closed_block_all_filters("S-1-5-21-FOREIGN", &exemptions, KillSwitchProtocols::ALL);
    let permits: Vec<u64> = filters
        .iter()
        .filter_map(|f| f.local_interface_luid)
        .collect();
    assert!(
        permits.contains(&FOREIGN),
        "the corporate tunnel keeps its egress"
    );

    // Without the claim nothing changes: the exemption is opt-in on evidence,
    // not a hole that is always open.
    let strict = FailClosedExemptions {
        foreign_tunnel_luids: Vec::new(),
        ..exemptions.clone()
    };
    let strict_permits: Vec<u64> =
        fail_closed_block_all_filters("S-1-5-21-FOREIGN", &strict, KillSwitchProtocols::ALL)
            .iter()
            .filter_map(|f| f.local_interface_luid)
            .collect();
    assert!(!strict_permits.contains(&FOREIGN));
}

/// Our own additional route is already permitted by its own field; listing it
/// twice would emit two filters with the same purpose and different ids.
#[test]
fn our_own_tunnel_is_not_permitted_twice() {
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: Vec::new(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: vec![LUID],
        primary_dest_ips: Vec::new(),
        allow_dns_over_primary: false,
        known_direct_ips: Vec::new(),
        probe_target_ips: Vec::new(),
        secondary_luid: LUID,
    };
    let with_ours =
        fail_closed_block_all_filters("S-1-5-21-FOREIGN", &exemptions, KillSwitchProtocols::ALL);
    // Same world, minus the redundant claim.
    let without = fail_closed_block_all_filters(
        "S-1-5-21-FOREIGN",
        &FailClosedExemptions {
            foreign_tunnel_luids: Vec::new(),
            ..exemptions.clone()
        },
        KillSwitchProtocols::ALL,
    );
    assert_eq!(
        with_ours.len(),
        without.len(),
        "our own tunnel is already permitted; claiming it again adds nothing",
    );
}

/// regression gate. `FwpmFilterAdd0` rejects a condition the
/// target layer does not expose (`FWP_E_CONDITION_NOT_FOUND`) — 3 020
/// kill-switch filters per HW run silently never installed because the
/// packet layer has no `FWPM_CONDITION_IP_PROTOCOL` and the mock engine
/// accepted them anyway. Every public emitter must produce specs whose
/// conditions are expressible at their layer (the mock now enforces the
/// same rule at add time; this test pins it at the codegen source).
#[test]
fn every_emitted_filter_is_expressible_at_its_layer() {
    let sid = "S-1-5-21-REG";
    // Both families: a v6 condition on a v4 layer installs and enforces
    // nothing, which is exactly what this test exists to catch.
    let ips = [
        IpAddr::V4(ip(203, 0, 113, 5)),
        IpAddr::V4(ip(198, 51, 100, 7)),
        v6("2001:db8::5"),
    ];
    let apps = ["C:\\Apps\\tunnel.exe".to_string()];
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        bootstrap_server_ips_v6: vec!["2001:db8:ffff::7".parse().expect("literal")],
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
        local_subnets_v6: vec![("2001:db8:1::".parse().expect("literal"), 64)],
        foreign_tunnel_luids: Vec::new(),
        primary_dest_ips: vec![ip(198, 51, 100, 200)],
        allow_dns_over_primary: true,
        known_direct_ips: vec![ip(203, 0, 113, 68)],
        probe_target_ips: vec![ip(10, 91, 192, 1)],
        secondary_luid: 0,
    };
    let mut all = Vec::new();
    all.extend(kill_switch_filters(
        sid,
        &ips,
        LUID,
        KillSwitchProtocols::ALL,
    ));
    all.extend(app_kill_switch_filters(
        sid,
        &apps,
        LUID,
        KillSwitchProtocols::ALL,
    ));
    all.extend(catch_all_kill_switch_filters(
        sid,
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    ));
    all.extend(fail_closed_block_destinations(
        sid,
        &ips,
        KillSwitchProtocols::ALL,
    ));
    all.extend(fail_closed_block_apps(sid, &apps, KillSwitchProtocols::ALL));
    all.extend(fail_closed_block_all_filters(
        sid,
        &exemptions,
        KillSwitchProtocols::ALL,
    ));
    assert!(!all.is_empty());
    for f in &all {
        assert!(
            f.validate_layer_conditions().is_ok(),
            "filter has a condition its layer cannot express: {f:?}"
        );
    }
}

#[test]
fn catch_all_disabled_on_zero_luid() {
    let mut r = full_resolution();
    r.secondary_luid = 0;
    assert!(catch_all_kill_switch_filters(
        "S",
        &r,
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL
    )
    .is_empty());
}

#[test]
fn catch_all_not_armed_without_server_ips() {
    let mut r = full_resolution();
    r.bootstrap_server_ips.clear();
    assert!(
        catch_all_kill_switch_filters(
            "S",
            &r,
            &FailClosedExemptions::default(),
            KillSwitchProtocols::ALL
        )
        .is_empty(),
        "no server exemption → don't arm (avoid trapping the tunnel's reconnect)"
    );
}

#[test]
fn catch_all_disabled_when_no_protocol_selected() {
    let empty = KillSwitchProtocols::from_bits(0);
    assert!(
        catch_all_kill_switch_filters(
            "S",
            &full_resolution(),
            &FailClosedExemptions::default(),
            empty
        )
        .is_empty(),
        "an empty protocol mask arms no block"
    );
}

#[test]
fn catch_all_emits_exemptions_and_block() {
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    // ALE layer: egress + loopback + link-local + broadcast +
    //   local-network-control + 1 server + 1 subnet + block = 8.
    let ale: Vec<_> = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .collect();
    assert_eq!(ale.len(), 8, "ALE: 7 exemptions + 1 catch-all block");
    assert_eq!(
        ale.iter()
            .filter(|f| f.local_interface_luid == Some(LUID))
            .count(),
        1,
        "exactly one egress-via-secondary permit at the ALE layer"
    );
    assert_eq!(
        ale.iter().filter(|f| f.remote_subnet.is_some()).count(),
        4,
        "loopback + link-local + local-network-control + LAN subnet"
    );
    // The v4 twin of the `ff02::/16` exemption: mDNS/LLMNR/IGMP live here
    // and never leave the link, so cutting them only breaks discovery.
    assert!(ale.iter().any(|f| f.action == WfpAction::Permit
        && f.remote_subnet == Some((Ipv4Addr::new(224, 0, 0, 0), 24))));
    assert_eq!(
        ale.iter().filter(|f| f.remote_ip.is_some()).count(),
        2,
        "VPN server + broadcast hosts"
    );
    assert_eq!(
        ale.iter().filter(|f| f.action == WfpAction::Block).count(),
        1,
        "exactly one ALE catch-all block"
    );
    // Packet layer: egress + loopback + link-local + broadcast +
    //   local-network-control + 1 server + 1 subnet + 4 named protocol
    //   blocks = 11 (one block per ICMP/IGMP/GRE/ESP, no agnostic
    //   block-all).
    let pkt: Vec<_> = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
        .collect();
    assert_eq!(
        pkt.len(),
        11,
        "packet layer mirrors the ALE exemptions + named blocks"
    );
    assert_eq!(
        pkt.iter()
            .filter(|f| f.local_interface_luid == Some(LUID))
            .count(),
        1,
        "exactly one egress-via-secondary permit at the packet layer"
    );
    assert_eq!(
        pkt.iter().filter(|f| f.action == WfpAction::Block).count(),
        4,
        "one packet block per named protocol (ICMP/IGMP/GRE/ESP)"
    );
    assert!(
        pkt.iter()
            .filter(|f| f.action == WfpAction::Block)
            .all(|f| f.ip_protocol.is_some()),
        "16.HW-0716: no protocol-agnostic packet block-all"
    );
}

#[test]
fn catch_all_covers_icmp_at_packet_layer() {
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    // A packet-layer block with no destination scope drops ICMP/ping the
    // instant the secondary adapter drops; a packet-layer egress permit keeps it flowing
    // while the tunnel is up. This is the 0704 P2 fix for the mode-B ping
    // leak.
    let has_packet_block = out
        .iter()
        .any(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block);
    let has_packet_egress = out.iter().any(|f| {
        f.layer == WfpLayerKey::OutboundTransportV4
            && f.action == WfpAction::Permit
            && f.local_interface_luid == Some(LUID)
    });
    assert!(
        has_packet_block,
        "ping must be blockable at the packet layer"
    );
    assert!(
        has_packet_egress,
        "packets egressing the secondary adapter stay permitted"
    );
}

#[test]
fn catch_all_no_packet_layer_when_only_tcp_udp_selected() {
    let tcp_udp = KillSwitchProtocols::from_bits(0x03); // tcp + udp only
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        tcp_udp,
    );
    assert!(
        out.iter()
            .all(|f| f.layer != WfpLayerKey::OutboundTransportV4),
        "no V4 packet-layer filters when the mask selects only TCP/UDP \
         (the IPv6 catch-all coverage is orthogonal to the V4 protocol mask)"
    );
}

#[test]
fn the_catch_all_respects_the_protocol_mask_like_its_fail_closed_twin() {
    // With TCP and UDP both unticked the mode-B catch-all installed its ALE
    // block anyway: the checkboxes did nothing, while the same choice in the
    // fail-closed path was honoured.
    let resolution = full_resolution();
    let exemptions = FailClosedExemptions::default();
    let icmp_only = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: true,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = catch_all_kill_switch_filters("S-1-5-21-A", &resolution, &exemptions, icmp_only);
    assert!(
        !out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV4
            && f.action == WfpAction::Block
            && f.remote_ip.is_none()
            && f.remote_subnet.is_none()),
        "no ALE block-all may install when neither TCP nor UDP is selected"
    );
    assert!(
        out.iter()
            .any(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block),
        "the packet-layer protocols the user DID select still block"
    );

    let tcp_only = KillSwitchProtocols {
        tcp: true,
        udp: false,
        icmp: false,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = catch_all_kill_switch_filters("S-1-5-21-A", &resolution, &exemptions, tcp_only);
    let block_all = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Block
                && f.remote_ip.is_none()
                && f.remote_subnet.is_none()
        })
        .expect("TCP selected → an ALE block-all");
    assert_eq!(
        block_all.ip_protocol,
        Some(PROTO_TCP),
        "one protocol selected narrows the block; the ALE layer carries that condition"
    );
}

#[test]
fn catch_all_block_weight_sits_between_secondary_and_primary_bands() {
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let ale: Vec<_> = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .collect();
    let block = ale.iter().find(|f| f.action == WfpAction::Block).unwrap();
    assert!(
        block.weight > 0x0010_0000 && block.weight < 0x0020_0000,
        "block {:#x} must sit between the secondary and primary rule bands so \
         primary exceptions escape and secondary destinations get killed",
        block.weight
    );
    for permit in ale.iter().filter(|f| f.action == WfpAction::Permit) {
        assert!(
            permit.weight > block.weight,
            "every ALE exemption permit must outrank the catch-all block"
        );
    }
}

#[test]
fn catch_all_block_is_unconditional_on_destination() {
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let block = out
        .iter()
        .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
        .unwrap();
    assert!(block.remote_ip.is_none());
    assert!(block.remote_subnet.is_none());
    assert!(block.local_interface_luid.is_none());
    assert_eq!(
        block.user_sid.as_deref(),
        Some("S"),
        "still scoped to the user — never blocks other users / system"
    );
}

#[test]
fn catch_all_user_sid_stamped_on_ale_filters_only() {
    let out = catch_all_kill_switch_filters(
        "S-1-5-21-Z",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    for f in &out {
        match f.layer {
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-Z"))
            }
            WfpLayerKey::OutboundIpPacketV4
            | WfpLayerKey::OutboundIpPacketV6
            | WfpLayerKey::OutboundTransportV4 => {
                assert_eq!(f.user_sid, None, "no ALE_USER_ID below the ALE layers")
            }
        }
    }
}

#[test]
fn catch_all_ids_deterministic_and_distinct() {
    let a = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let b = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let ids_a: Vec<u64> = a.iter().map(|f| f.id.raw).collect();
    let ids_b: Vec<u64> = b.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids_a, ids_b, "same inputs → identical ids");
    let unique: std::collections::HashSet<u64> = ids_a.iter().copied().collect();
    assert_eq!(unique.len(), ids_a.len(), "all catch-all ids must differ");
}
