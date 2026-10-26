use super::*;

// ── Catch-all kill-switch ───────────────────────────────────────────────

/// Naming a corporate tunnel never makes it an exit from a blanket posture:
/// neither blanket emits a permit for it, so a tunnel holding a default route
/// cannot carry the protected traffic once ours is down. What it may carry is
/// its own networks, through [`foreign_tunnel_permits`], on every layer the
/// blanket blocks at.
#[test]
fn a_named_foreign_tunnel_is_no_exit_from_either_blanket_posture() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0002;
    let sid = "S-1-5-21-F";
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        foreign_tunnel_luids: vec![FOREIGN],
        secondary_luid: LUID,
        ..FailClosedExemptions::default()
    };
    let unnamed = FailClosedExemptions {
        foreign_tunnel_luids: Vec::new(),
        ..exemptions.clone()
    };
    let resolution = full_resolution();
    let up = catch_all_kill_switch_filters(sid, &resolution, &exemptions, KillSwitchProtocols::ALL);
    let down = fail_closed_block_all_filters(sid, &exemptions, KillSwitchProtocols::ALL);
    for (posture, filters, without) in [
        (
            "tunnel up",
            &up,
            catch_all_kill_switch_filters(sid, &resolution, &unnamed, KillSwitchProtocols::ALL),
        ),
        (
            "tunnel down",
            &down,
            fail_closed_block_all_filters(sid, &unnamed, KillSwitchProtocols::ALL),
        ),
    ] {
        assert!(
            filters
                .iter()
                .all(|f| f.local_interface_luid != Some(FOREIGN)),
            "{posture}: the blanket itself permits nothing through the foreign tunnel",
        );
        assert_eq!(
            filters, &without,
            "{posture}: the luid list does not reach the blanket"
        );

        let networks = [
            foreign_net(FOREIGN, "10.77.0.0/16"),
            foreign_net(FOREIGN, "fd00:77::/48"),
        ];
        let permits = foreign_tunnel_permits(sid, filters, &networks, LUID);
        for layer in [
            WfpLayerKey::AleAuthConnectV4,
            WfpLayerKey::OutboundTransportV4,
            WfpLayerKey::AleAuthConnectV6,
            WfpLayerKey::OutboundTransportV6,
        ] {
            let permit = permits
                .iter()
                .find(|f| f.layer == layer && f.action == WfpAction::Permit)
                .unwrap_or_else(|| panic!("{posture}: no foreign permit at {layer:?}"));
            assert_eq!(permit.local_interface_luid, Some(FOREIGN));
            assert!(
                permit.remote_subnet.is_some() || permit.remote_subnet_v6.is_some(),
                "{posture}: the permit at {layer:?} names the tunnel's networks, not everything",
            );
        }
    }
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
        foreign_tunnel_networks: Vec::new(),
        primary_dest_ips: vec![ip(198, 51, 100, 200)],
        allow_dns_over_primary: true,
        dns_servers: Vec::new(),
        probe_target_ips: vec![ip(10, 91, 192, 1)],
        secondary_luid: 0,
        guest_network_luids: Vec::new(),
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
        "no protocol-agnostic packet block-all"
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
            | WfpLayerKey::OutboundTransportV4
            | WfpLayerKey::OutboundTransportV6
            | WfpLayerKey::IpForwardV4
            | WfpLayerKey::IpForwardV6 => {
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

fn foreign_net(luid: u64, text: &str) -> ForeignTunnelNetwork {
    ForeignTunnelNetwork {
        luid,
        network: nrr_shared::ip_block::IpBlock::parse(text).expect("network"),
    }
}

/// The permits follow the blocks, name the tunnel's own networks only, and
/// skip our tunnel and an unusable LUID.
#[test]
fn foreign_tunnel_permits_follow_the_posture_blocks_only() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0003;
    let sid = "S-1-5-21-F";
    let pins = kill_switch_filters(
        sid,
        &[IpAddr::V4(ip(203, 0, 113, 5))],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let networks = [
        foreign_net(FOREIGN, "10.77.0.0/16"),
        foreign_net(FOREIGN, "fd00:77::/48"),
        foreign_net(LUID, "10.8.0.0/24"),
        foreign_net(0, "10.9.0.0/24"),
    ];
    let permits = foreign_tunnel_permits(sid, &pins, &networks, LUID);
    assert!(!permits.is_empty());
    assert!(permits
        .iter()
        .all(|f| f.local_interface_luid == Some(FOREIGN)
            && f.action == WfpAction::Permit
            && f.remote_subnet == Some((ip(10, 77, 0, 0), 16))));
    assert!(
        permits.iter().all(|f| !f.layer.is_v6()),
        "no v6 block, no v6 permit",
    );
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
    ] {
        let heaviest_pin = pins
            .iter()
            .filter(|f| f.layer == layer && f.action == WfpAction::Block)
            .map(|f| f.weight)
            .max()
            .expect("a pin block at every v4 layer");
        let permit = permits
            .iter()
            .find(|f| f.layer == layer)
            .expect("a permit at every pinned layer");
        assert!(permit.weight > heaviest_pin, "{layer:?}");
    }

    let mut user_block = pins[0].clone();
    user_block.action = WfpAction::Block;
    user_block.weight = crate::wfp_bands::BASE_BLOCK;
    assert!(foreign_tunnel_permits(sid, &[user_block], &networks, LUID).is_empty());
    assert!(foreign_tunnel_permits(sid, &pins, &[], LUID).is_empty());
}

/// A user Block's packet mirrors are the user's, not a posture: no permit is
/// owed for them.
#[test]
fn a_user_block_mirror_on_a_packet_layer_is_no_posture_block() {
    let mirror = |layer| WfpFilterSpec {
        layer,
        action: WfpAction::Block,
        remote_ip: None,
        remote_ip_set: vec![ip(10, 77, 9, 9)],
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: crate::wfp_bands::BASE_BLOCK + 3,
        id: nrr_platform_api::types::WfpFilterId { raw: 7 },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: None,
        remote_subnet_v6: None,
        ip_protocol: None,
        remote_subnet_set: Vec::new(),
    };
    let mirrors = [
        mirror(WfpLayerKey::OutboundIpPacketV4),
        mirror(WfpLayerKey::OutboundIpPacketV6),
    ];
    assert!(!has_posture_block(&mirrors));
}

fn pins_for(sid: &str) -> Vec<WfpFilterSpec> {
    kill_switch_filters(
        sid,
        &[IpAddr::V4(ip(203, 0, 113, 5))],
        LUID,
        KillSwitchProtocols::ALL,
    )
}

/// The networks of one tunnel ride a single filter per layer as OR'd subnet
/// conditions: the filter count does not grow with the routes a corporate VPN
/// pushes.
#[test]
fn a_tunnels_networks_share_one_filter_per_layer() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0004;
    let sid = "S-1-5-21-F";
    let pins = pins_for(sid);
    let networks: Vec<ForeignTunnelNetwork> = (0..40)
        .map(|n| foreign_net(FOREIGN, &format!("10.{}.0.0/16", n + 1)))
        .collect();
    let permits = foreign_tunnel_permits(sid, &pins, &networks, LUID);
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
    ] {
        let at_layer: Vec<_> = permits
            .iter()
            .filter(|f| f.layer == layer && f.action == WfpAction::Permit)
            .collect();
        assert_eq!(at_layer.len(), 1, "{layer:?}: one filter for the tunnel");
        let permit = at_layer[0];
        assert_eq!(permit.local_interface_luid, Some(FOREIGN));
        assert_eq!(permit.remote_subnet_set.len(), 40, "{layer:?}");
        assert!(permit.remote_subnet.is_none() && permit.remote_subnet_v6.is_none());
        assert!(permit.validate_layer_conditions().is_ok());
        assert!(
            permit.covers_v4(ip(10, 7, 3, 3)),
            "inside a carried network"
        );
        assert!(!permit.covers_v4(ip(10, 99, 0, 1)), "outside every network");
    }
}

/// A rebuilt set with a different membership mints a different id, so the
/// reconcile swaps the filter rather than keeping a stale condition list.
#[test]
fn a_changed_network_list_changes_the_permit_id() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0004;
    let sid = "S-1-5-21-F";
    let pins = pins_for(sid);
    let two = [
        foreign_net(FOREIGN, "10.1.0.0/16"),
        foreign_net(FOREIGN, "10.2.0.0/16"),
    ];
    let three = [two[0], two[1], foreign_net(FOREIGN, "10.3.0.0/16")];
    let id_of = |nets: &[ForeignTunnelNetwork]| {
        foreign_tunnel_permits(sid, &pins, nets, LUID)
            .into_iter()
            .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
            .map(|f| f.id)
            .expect("a permit")
    };
    assert_ne!(id_of(&two), id_of(&three));
    let reversed = [two[1], two[0]];
    assert_eq!(id_of(&two), id_of(&reversed), "order is not meaning");
}

/// Two tunnels get a filter each, at their own weight, and a permit never names
/// the other tunnel's networks.
#[test]
fn each_foreign_tunnel_has_its_own_permit() {
    const A: u64 = 0x00AB_CDEF_0000_000A;
    const B: u64 = 0x00AB_CDEF_0000_000B;
    let sid = "S-1-5-21-F";
    let pins = pins_for(sid);
    let networks = [
        foreign_net(A, "10.1.0.0/16"),
        foreign_net(A, "10.2.0.0/16"),
        foreign_net(B, "172.20.0.0/16"),
    ];
    let permits = foreign_tunnel_permits(sid, &pins, &networks, LUID);
    let ale: Vec<_> = permits
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4 && f.action == WfpAction::Permit)
        .collect();
    assert_eq!(ale.len(), 2);
    assert_ne!(ale[0].weight, ale[1].weight);
    assert_ne!(ale[0].id, ale[1].id);
    let of = |luid| {
        ale.iter()
            .find(|f| f.local_interface_luid == Some(luid))
            .copied()
            .expect("a permit per tunnel")
    };
    assert!(of(A).covers_v4(ip(10, 2, 0, 9)) && !of(A).covers_v4(ip(172, 20, 0, 9)));
    assert_eq!(of(B).remote_subnet, Some((ip(172, 20, 0, 0), 16)));
}

/// Past the per-tunnel cap the rest stay cut, and the cut is counted so the
/// caller can say so; a tunnel under the cap loses nothing.
#[test]
fn a_tunnel_past_the_cap_is_cut_and_counted() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0004;
    let sid = "S-1-5-21-F";
    let pins = pins_for(sid);
    let cap = crate::wfp_bands::FOREIGN_TUNNEL_MAX_NETWORKS;
    let many: Vec<ForeignTunnelNetwork> = (0..=cap)
        .map(|n| foreign_net(FOREIGN, &format!("10.{}.{}.0/24", n / 200 + 1, n % 200)))
        .collect();
    let counted = foreign_tunnel_permits_counted(sid, &pins, &many, LUID);
    assert_eq!(counted.cut, (1, 0));
    let permit = counted
        .filters
        .iter()
        .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4 && f.action == WfpAction::Permit)
        .expect("the tunnel is still permitted");
    assert_eq!(permit.remote_subnet_set.len(), cap);
    assert!(permit.validate_layer_conditions().is_ok());

    let fits = foreign_tunnel_permits_counted(sid, &pins, &many[..cap], LUID);
    assert_eq!(fits.cut, (0, 0));
}

/// The layers below ALE carry no user id, so their foreign permits are
/// machine-wide. They must at least stay as narrow as the layer lets them: the
/// tunnel's own networks AND its egress interface, in either family.
#[test]
fn the_user_less_layers_keep_the_networks_and_the_interface() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0003;
    let sid = "S-1-5-21-F";
    let mut blocking = pins_for(sid);
    blocking.extend(catch_all_v6_filters(
        sid,
        LUID,
        &[],
        &[],
        KillSwitchProtocols::ALL,
    ));
    let networks = [
        foreign_net(FOREIGN, "10.77.0.0/16"),
        foreign_net(FOREIGN, "10.78.0.0/16"),
        foreign_net(FOREIGN, "fd00:77::/48"),
        foreign_net(FOREIGN, "fd00:78::/48"),
    ];
    let permits = foreign_tunnel_permits(sid, &blocking, &networks, LUID);
    let below_ale: Vec<_> = permits
        .iter()
        .filter(|f| {
            f.action == WfpAction::Permit
                && matches!(
                    f.layer,
                    WfpLayerKey::OutboundTransportV4 | WfpLayerKey::OutboundTransportV6
                )
        })
        .collect();
    assert!(
        below_ale
            .iter()
            .any(|f| f.layer == WfpLayerKey::OutboundTransportV4)
            && below_ale
                .iter()
                .any(|f| f.layer == WfpLayerKey::OutboundTransportV6),
        "both user-less layers carry a permit: {below_ale:?}",
    );
    for f in below_ale {
        assert_eq!(f.user_sid, None, "{f:?}");
        assert_eq!(f.local_interface_luid, Some(FOREIGN), "{f:?}");
        assert!(
            f.remote_subnet.is_some()
                || f.remote_subnet_v6.is_some()
                || !f.remote_subnet_set.is_empty(),
            "{f:?} must name the tunnel's networks",
        );
        assert!(f.remote_ip.is_none() && f.remote_ip_set.is_empty());
        assert!(f.ip_protocol.is_none() && f.remote_port.is_none());
    }
    for f in permits.iter().filter(|f| {
        f.action == WfpAction::Permit
            && matches!(
                f.layer,
                WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
            )
    }) {
        assert_eq!(f.user_sid.as_deref(), Some(sid), "{f:?}");
    }
}

fn doh_for(sid: &str) -> Vec<WfpFilterSpec> {
    doh_dot_block_filters(sid, &[IpAddr::V4(ip(8, 8, 8, 8))], true)
}

/// The lockdown is restated above a corporate tunnel's permit, for what leaves
/// through that tunnel only, so a public resolver the tunnel routes is still
/// cut while a corporate host is not.
#[test]
fn the_dns_lockdown_outranks_a_foreign_permit_for_what_leaves_through_it() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0006;
    let sid = "S-1-5-21-F";
    let pins = pins_for(sid);
    let networks = [foreign_net(FOREIGN, "8.8.8.0/24")];
    let permits = foreign_tunnel_permits(sid, &pins, &networks, LUID);
    let permit = permits
        .iter()
        .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4 && f.action == WfpAction::Permit)
        .expect("the resolver's network is permitted through the tunnel");
    let doh = doh_for(sid);
    let mut emitted = pins;
    emitted.extend(permits.iter().cloned());
    let vetoes = doh_foreign_vetoes(sid, &doh, &emitted, &[FOREIGN], LUID);
    assert!(!vetoes.is_empty());
    let originals = doh
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .count();
    assert_eq!(
        vetoes.len(),
        originals,
        "one restatement per lockdown block"
    );
    let mut ids: Vec<_> = vetoes.iter().map(|f| f.id).collect();
    ids.sort_by_key(|id| id.raw);
    ids.dedup();
    assert_eq!(ids.len(), vetoes.len(), "distinct ids");
    for v in &vetoes {
        assert_eq!(v.action, WfpAction::Block);
        assert_eq!(v.local_interface_luid, Some(FOREIGN));
        assert_eq!(v.user_sid.as_deref(), Some(sid));
        assert!(v.weight > permit.weight, "the lockdown outranks the permit");
        assert!(v.weight >= crate::wfp_bands::DOH_FOREIGN_VETO_BASE);
        assert!(v.weight < crate::wfp_bands::APP_EXEMPT_BASE);
        assert!(v.remote_port.is_some(), "the same ports and protocols");
    }
}

/// No permit through a tunnel, nothing to restate; an unusable LUID is never
/// given a restatement, and our own tunnel only beside a permit through it.
#[test]
fn the_dns_lockdown_is_restated_only_where_a_foreign_permit_exists() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0006;
    let sid = "S-1-5-21-F";
    let doh = doh_for(sid);
    assert!(
        doh_foreign_vetoes(sid, &doh, &[], &[FOREIGN], LUID).is_empty(),
        "no permit beside the lockdown",
    );
    let pins = pins_for(sid);
    let permits = foreign_tunnel_permits(sid, &pins, &[foreign_net(FOREIGN, "8.8.8.0/24")], LUID);
    let mut emitted = pins;
    emitted.extend(permits);
    assert!(doh_foreign_vetoes(sid, &doh, &emitted, &[LUID, 0], LUID).is_empty());
}

/// "Everything" with our tunnel up: the block-all lets the user's traffic out
/// through our tunnel at the exemption band, above the lockdown's own band. A
/// browser's DoH then leaves through the tunnel, names never reach the
/// resolver, and the rules on names stop working for that browser. The lockdown
/// is restated for our tunnel too, above that permit.
#[test]
fn the_dns_lockdown_outranks_the_permit_for_our_own_tunnel() {
    let sid = "S-1-5-21-F";
    let own_egress = exempt_egress(sid, LUID, crate::wfp_bands::CATCHALL_EXEMPT_BASE);
    let doh = doh_for(sid);
    let vetoes = doh_foreign_vetoes(sid, &doh, std::slice::from_ref(&own_egress), &[], LUID);
    assert!(
        vetoes
            .iter()
            .any(|v| v.local_interface_luid == Some(LUID) && v.weight > own_egress.weight),
        "DoH leaves through our own tunnel past the lockdown"
    );
}

/// An address pinned to our tunnel inside a foreign network is cut for egress
/// through that tunnel, above the network's permit; the rest of the network
/// stays permitted.
#[test]
fn a_pinned_address_inside_a_foreign_network_stays_cut_through_that_tunnel() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0005;
    let sid = "S-1-5-21-F";
    let pinned = ip(10, 77, 1, 5);
    let pins = kill_switch_filters(
        sid,
        &[IpAddr::V4(pinned), IpAddr::V4(ip(203, 0, 113, 5))],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let out = foreign_tunnel_permits(sid, &pins, &[foreign_net(FOREIGN, "10.77.0.0/16")], LUID);

    let permit = out
        .iter()
        .find(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::AleAuthConnectV4)
        .expect("the network is permitted");
    let vetoes: Vec<_> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
        .collect();
    assert_eq!(vetoes.len(), 1, "{vetoes:?}");
    let veto = vetoes[0];
    assert_eq!(veto.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(veto.local_interface_luid, Some(FOREIGN));
    assert_eq!(veto.remote_ip_set, vec![pinned]);
    assert!(veto.weight > permit.weight, "the narrower rule outranks");
    assert!(veto.weight < crate::wfp_bands::APP_EXEMPT_BASE);
}

/// ICMP and the other non-TCP/UDP protocols to a pinned address take the
/// transport layer, where the foreign permit is protocol-agnostic: the veto
/// must be there too, per protocol the pin blocks, and nowhere else.
#[test]
fn a_pinned_address_inside_a_foreign_network_is_cut_at_the_transport_layer_too() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0005;
    let sid = "S-1-5-21-F";
    let pinned = ip(10, 77, 1, 5);
    let pins = kill_switch_filters(
        sid,
        &[IpAddr::V4(pinned), IpAddr::V4(ip(203, 0, 113, 5))],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let out = foreign_tunnel_permits(sid, &pins, &[foreign_net(FOREIGN, "10.77.0.0/16")], LUID);
    let permit = out
        .iter()
        .find(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::OutboundTransportV4)
        .expect("the network is permitted at the transport layer");
    let vetoes: Vec<_> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
        .collect();
    let mut protos: Vec<_> = vetoes.iter().filter_map(|f| f.ip_protocol).collect();
    protos.sort_unstable();
    let mut blocked: Vec<_> = pins
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
        .filter_map(|f| f.ip_protocol)
        .collect();
    blocked.sort_unstable();
    blocked.dedup();
    assert_eq!(protos, blocked, "one veto per protocol the pin blocks");
    for veto in vetoes {
        assert_eq!(veto.local_interface_luid, Some(FOREIGN));
        assert_eq!(veto.remote_ip_set, vec![pinned], "only the address inside");
        assert!(veto.weight > permit.weight, "the narrower rule outranks");
        assert!(veto.weight < crate::wfp_bands::PACKET_PERMIT_BASE);
    }
}

/// A protocol the user left unprotected is not blocked for the pin, so the veto
/// must not invent a block for it.
#[test]
fn the_transport_veto_follows_the_protocols_the_pin_blocks() {
    const FOREIGN: u64 = 0x00AB_CDEF_0000_0005;
    let sid = "S-1-5-21-F";
    let pins = kill_switch_filters(
        sid,
        &[IpAddr::V4(ip(10, 77, 1, 5))],
        LUID,
        KillSwitchProtocols {
            tcp: true,
            udp: true,
            icmp: false,
            igmp: false,
            gre: false,
            esp: true,
            other: false,
        },
    );
    let out = foreign_tunnel_permits(sid, &pins, &[foreign_net(FOREIGN, "10.77.0.0/16")], LUID);
    let protos: Vec<_> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
        .filter_map(|f| f.ip_protocol)
        .collect();
    assert_eq!(protos.len(), 1, "{protos:?}");
    assert!(!protos.contains(&1), "ICMP was not protected");
}
