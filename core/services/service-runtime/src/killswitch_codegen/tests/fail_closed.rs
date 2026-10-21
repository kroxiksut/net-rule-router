use super::*;

// ── Fail-closed posture ─────────────────────────────────────────────────

#[test]
fn fail_closed_mode_a_blocks_each_protected_dest_at_both_layers() {
    // All protocols: per dest → 1 ALE block (TCP/UDP) + 4 named packet
    // blocks (ICMP/IGMP/GRE/ESP, no agnostic block-all).
    let out = fail_closed_block_destinations(
        "S",
        &v4_pins([ip(203, 0, 113, 5), ip(198, 51, 100, 8)]),
        KillSwitchProtocols::ALL,
    );
    let chunks = pack_v4([ip(203, 0, 113, 5), ip(198, 51, 100, 8)]).len();
    assert_eq!(out.len(), chunks * 5);
    for f in &out {
        assert_eq!(f.action, WfpAction::Block);
        assert_eq!(
            f.local_interface_luid, None,
            "fail-closed block has no egress condition — the secondary adapter is gone"
        );
    }
    let ale = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .count();
    let pkt = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
        .count();
    assert_eq!((ale, pkt), (chunks, chunks * 4));
    // ALE blocks are per-SID; packet blocks are system-wide (no ALE_USER_ID).
    for f in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
    {
        assert_eq!(f.user_sid.as_deref(), Some("S"));
    }
    for f in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
    {
        assert_eq!(f.user_sid, None, "packet layer has no ALE_USER_ID");
    }
    assert!(out.iter().any(|f| f.covers_v4(ip(203, 0, 113, 5))));
    assert!(out.iter().any(|f| f.covers_v4(ip(198, 51, 100, 8))));
}

#[test]
fn fail_closed_mode_a_outranks_rule_band_and_skips_loopback() {
    let out = fail_closed_block_destinations(
        "S",
        &v4_pins([ip(127, 0, 0, 1), ip(203, 0, 113, 5)]),
        KillSwitchProtocols::ALL,
    );
    // loopback skipped; the one real dest → ALE block + 4 named packet blocks.
    assert_eq!(out.len(), 5, "loopback is never blocked");
    assert!(out.iter().all(|f| f.covers_v4(ip(203, 0, 113, 5))));
    assert!(!out.iter().any(|f| f.covers_v4(ip(127, 0, 0, 1))));
    let ale = out
        .iter()
        .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .unwrap();
    assert!(
        ale.weight > RULE_PRIMARY_BAND,
        "fail-closed ALE block {:#x} must outrank the rule permit it overrides",
        ale.weight
    );
}

#[test]
fn fail_closed_mode_a_icmp_only_emits_single_packet_block() {
    // Only ICMP selected: no ALE block (no TCP/UDP), one packet block proto=1.
    let protos = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: true,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = fail_closed_block_destinations("S", &v4_pins([ip(203, 0, 113, 5)]), protos);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].layer, WfpLayerKey::OutboundTransportV4);
    assert_eq!(out[0].action, WfpAction::Block);
    assert_eq!(out[0].ip_protocol, Some(PROTO_ICMP));
    assert!(out[0].covers_v4(ip(203, 0, 113, 5)));
}

#[test]
fn fail_closed_no_protocols_yields_no_filters() {
    let none = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: false,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    assert!(fail_closed_block_destinations("S", &v4_pins([ip(198, 51, 100, 8)]), none).is_empty());
    assert!(fail_closed_block_all_filters("S", &FailClosedExemptions::default(), none).is_empty());
}

#[test]
fn fail_closed_allow_dns_over_primary_permits_port_53_to_the_system_resolvers_only() {
    // Opt-in: with `allow_dns_over_primary` the block-all set gains port-53
    // ALE permits, one UDP+TCP pair per system resolver and nothing wider;
    // off (the strict default) it must not, and with no resolver listed
    // there is nothing to permit.
    let strict = fail_closed_block_all_filters(
        "S",
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    assert!(
        !strict.iter().any(|f| f.remote_port == Some(53)),
        "strict block-all must NOT permit DNS over the primary link"
    );
    let unlisted = FailClosedExemptions {
        allow_dns_over_primary: true,
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &unlisted, KillSwitchProtocols::ALL);
    assert!(
        !out.iter().any(|f| f.remote_port == Some(53)),
        "no resolver listed: port 53 stays closed rather than open to any host"
    );

    let resolvers = [ip(192, 0, 2, 53), ip(192, 0, 2, 54)];
    let ex = FailClosedExemptions {
        allow_dns_over_primary: true,
        dns_servers: resolvers.iter().copied().map(IpAddr::V4).collect(),
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let dns: Vec<_> = out
        .iter()
        .filter(|f| {
            f.action == WfpAction::Permit
                && f.layer == WfpLayerKey::AleAuthConnectV4
                && f.remote_port == Some(53)
        })
        .collect();
    assert_eq!(dns.len(), 4, "UDP-53 + TCP-53 per resolver");
    for resolver in resolvers {
        assert!(dns
            .iter()
            .any(|f| f.remote_ip == Some(resolver) && f.ip_protocol == Some(17)));
        assert!(dns
            .iter()
            .any(|f| f.remote_ip == Some(resolver) && f.ip_protocol == Some(6)));
    }
    // Pinned to the resolvers: never a permit for any host on port 53.
    assert!(dns.iter().all(|f| f.remote_ip.is_some()));
    let ids: std::collections::HashSet<_> = dns.iter().map(|f| f.id).collect();
    assert_eq!(ids.len(), 4, "one id per resolver and protocol");
}

/// On a network whose only resolvers are IPv6 the port-53 permit must name
/// them at the v6 ALE layer; nothing below it cuts UDP or TCP.
#[test]
fn an_ipv6_only_network_keeps_its_resolver_reachable_under_the_block_all() {
    let resolver: Ipv6Addr = "2001:db8:53::1".parse().unwrap();
    let ex = FailClosedExemptions {
        allow_dns_over_primary: true,
        dns_servers: vec![IpAddr::V6(resolver)],
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let ale: Vec<_> = out
        .iter()
        .filter(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV6
                && f.action == WfpAction::Permit
                && f.remote_port == Some(53)
        })
        .collect();
    assert_eq!(ale.len(), 2, "UDP-53 and TCP-53 for the one resolver");
    for f in &ale {
        assert_eq!(f.remote_subnet_v6, Some((resolver, 128)));
        assert_eq!(f.user_sid.as_deref(), Some("S"));
    }
    assert!(ale.iter().any(|f| f.ip_protocol == Some(17)));
    assert!(ale.iter().any(|f| f.ip_protocol == Some(6)));
    assert!(
        out.iter()
            .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV6)
            .all(|f| !matches!(f.ip_protocol, Some(6) | Some(17))),
        "a block below ALE would still eat the query"
    );
    // Only the resolver: no v6 permit for any host on port 53, and nothing v4.
    assert!(out
        .iter()
        .filter(|f| f.remote_port == Some(53))
        .all(|f| f.layer == WfpLayerKey::AleAuthConnectV6));
    // Without the opt-in, no resolver permit at all.
    let strict = fail_closed_block_all_filters(
        "S",
        &FailClosedExemptions {
            dns_servers: vec![IpAddr::V6(resolver)],
            ..FailClosedExemptions::default()
        },
        KillSwitchProtocols::ALL,
    );
    assert!(!strict
        .iter()
        .any(|f| f.remote_subnet_v6 == Some((resolver, 128))));
}

#[test]
fn a_dual_stack_network_permits_both_families_and_never_a_link_local_resolver() {
    let v4 = ip(192, 0, 2, 53);
    let v6: Ipv6Addr = "2001:db8:53::1".parse().unwrap();
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    let ex = FailClosedExemptions {
        allow_dns_over_primary: true,
        dns_servers: vec![IpAddr::V4(v4), IpAddr::V6(v6), IpAddr::V6(link_local)],
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let port53: Vec<_> = out.iter().filter(|f| f.remote_port == Some(53)).collect();
    assert_eq!(
        port53.len(),
        4,
        "UDP and TCP for the v4 and the v6 resolver"
    );
    assert!(port53
        .iter()
        .any(|f| f.layer == WfpLayerKey::AleAuthConnectV4 && f.remote_ip == Some(v4)));
    assert!(
        port53
            .iter()
            .any(|f| f.layer == WfpLayerKey::AleAuthConnectV6
                && f.remote_subnet_v6 == Some((v6, 128)))
    );
    assert!(!out
        .iter()
        .any(|f| f.remote_subnet_v6 == Some((link_local, 128))));
    let ids: std::collections::HashSet<_> = out.iter().map(|f| f.id).collect();
    assert_eq!(ids.len(), out.len(), "every filter has its own id");
}

/// With another principal on the machine nothing v6 is emitted below ALE, and
/// the resolver keeps its ALE permits.
#[test]
fn with_other_principals_the_v6_resolver_keeps_its_ale_permits() {
    let resolver: Ipv6Addr = "2001:db8:53::1".parse().unwrap();
    let ex = FailClosedExemptions {
        allow_dns_over_primary: true,
        dns_servers: vec![IpAddr::V6(resolver)],
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters_for("S", &ex, KillSwitchProtocols::ALL, true);
    assert!(out
        .iter()
        .all(|f| f.layer != WfpLayerKey::OutboundTransportV6));
    assert_eq!(
        out.iter()
            .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV6 && f.remote_port == Some(53))
            .count(),
        2
    );
}

#[test]
fn fail_closed_block_all_permits_known_primary_at_packet_layer_above_block() {
    // a known-primary host earns a
    // packet-layer proto-agnostic permit that outranks the named packet
    // blocks, so ping/ICMP to it survives the block-all (the regional-site case).
    let primary = ip(203, 0, 113, 50);
    let ex = FailClosedExemptions {
        primary_dest_ips: vec![primary, ip(127, 0, 0, 1)], // loopback filtered
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let permit = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.remote_ip == Some(primary)
                && f.ip_protocol.is_none() // proto-agnostic → covers ICMP
        })
        .expect("known-primary packet permit present");
    // Loopback in the primary set is filtered (is_exempt_from_blocking):
    // the only 127/8 permit is the standard subnet exempt, never a per-host
    // primary permit keyed on 127.0.0.1.
    assert!(
        !out.iter().any(|f| f.remote_ip == Some(ip(127, 0, 0, 1))),
        "loopback host is skipped — no per-host primary permit for it"
    );
    // The permit must outrank every packet-layer block so ICMP escapes.
    for blk in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
    {
        assert!(
            permit.weight > blk.weight,
            "known-primary permit {:#x} must outrank packet block {:#x}",
            permit.weight,
            blk.weight
        );
    }
}

#[test]
fn fail_closed_block_all_exempts_known_direct_at_both_layers() {
    // a known-DIRECT destination has no
    // rule permit at all, so it needs BOTH an ALE exempt (TCP/UDP connects)
    // and a packet-layer permit (ICMP), each above its layer's block.
    let direct = ip(203, 0, 113, 68);
    let ex = FailClosedExemptions {
        known_direct_ips: vec![direct, ip(127, 0, 0, 1)], // loopback filtered
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let ale = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Permit
                && f.remote_ip == Some(direct)
        })
        .expect("known-direct ALE exempt present");
    let pkt = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.remote_ip == Some(direct)
                && f.ip_protocol.is_none()
        })
        .expect("known-direct packet permit present");
    // Distinct id kinds — an IP that is also a VPN server / known-primary
    // must not collide filter ids in one desired set.
    let overlap = FailClosedExemptions {
        bootstrap_server_ips: vec![direct],
        bootstrap_server_ips_v6: Vec::new(),
        primary_dest_ips: vec![direct],
        known_direct_ips: vec![direct],
        ..FailClosedExemptions::default()
    };
    let dup = fail_closed_block_all_filters("S", &overlap, KillSwitchProtocols::ALL);
    let ids: std::collections::HashSet<String> =
        dup.iter().map(|f| format!("{:?}", f.id)).collect();
    assert_eq!(
        ids.len(),
        dup.len(),
        "server/primary/direct twins keep distinct filter ids"
    );
    // Each permit outranks its own layer's block.
    let ale_block = out
        .iter()
        .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
        .expect("ALE block present");
    assert!(ale.weight > ale_block.weight);
    for blk in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
    {
        assert!(pkt.weight > blk.weight);
    }
    // The loopback entry is filtered — no per-host permit keyed on it.
    assert!(
        !out.iter().any(|f| f.remote_ip == Some(ip(127, 0, 0, 1))),
        "loopback never earns a known-direct permit"
    );
    // ALE half carries the user-SID scope like every kill-switch ALE filter.
    assert_eq!(ale.user_sid.as_deref(), Some("S"));
}

#[test]
fn fail_closed_block_all_exempts_liveness_probe_target_at_both_layers() {
    //  HW — the liveness probe's ICMP echo to the tunnel
    // next-hop is kernel-originated (no app-id): if the packet-layer ICMP
    // block eats it, the DEAD verdict can never recover and the block-all
    // never disarms. The probe target must earn an ALE exempt AND a
    // proto-agnostic packet permit, each above its layer's block.
    let next_hop = ip(10, 91, 192, 1);
    let ex = FailClosedExemptions {
        probe_target_ips: vec![next_hop],
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    let ale = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::AleAuthConnectV4
                && f.action == WfpAction::Permit
                && f.remote_ip == Some(next_hop)
        })
        .expect("probe-target ALE exempt present");
    let pkt = out
        .iter()
        .find(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Permit
                && f.remote_ip == Some(next_hop)
                && f.ip_protocol.is_none() // proto-agnostic → covers ICMP
        })
        .expect("probe-target packet permit present");
    let ale_block = out
        .iter()
        .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
        .expect("ALE block present");
    assert!(ale.weight > ale_block.weight);
    for blk in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4 && f.action == WfpAction::Block)
    {
        assert!(
            pkt.weight > blk.weight,
            "probe-target permit {:#x} must outrank packet block {:#x}",
            pkt.weight,
            blk.weight
        );
    }
    assert_eq!(ale.user_sid.as_deref(), Some("S"));
    // A next-hop that equals a bootstrap server IP keeps distinct ids.
    let overlap = FailClosedExemptions {
        bootstrap_server_ips: vec![next_hop],
        bootstrap_server_ips_v6: Vec::new(),
        probe_target_ips: vec![next_hop],
        ..FailClosedExemptions::default()
    };
    let dup = fail_closed_block_all_filters("S", &overlap, KillSwitchProtocols::ALL);
    let ids: std::collections::HashSet<String> =
        dup.iter().map(|f| format!("{:?}", f.id)).collect();
    assert_eq!(
        ids.len(),
        dup.len(),
        "server/probe twins keep distinct filter ids"
    );
}

#[test]
fn fail_closed_mode_b_blocks_all_except_exemptions() {
    let ex = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
        ..FailClosedExemptions::default()
    };
    let out = fail_closed_block_all_filters("S", &ex, KillSwitchProtocols::ALL);
    // ALE: loopback+link-local+broadcast+local-network-control+server+
    //   subnet + block-all = 7. Packet: same 6 exemptions + 4 named
    //   protocol blocks = 10 (ICMP/IGMP/GRE/ESP, no agnostic block-all).
    // IPv6: V6 ALE (loopback+link-local+link-local-multicast+block = 4)
    // + V6 transport (3 exemptions + ICMPv6/GRE/ESP = 6) = 10. Total 27.
    assert_eq!(out.len(), 27);
    let ale_block = out
        .iter()
        .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::AleAuthConnectV4)
        .unwrap();
    assert!(ale_block.remote_ip.is_none() && ale_block.remote_subnet.is_none());
    assert!(
        ale_block.weight > 0x0010_0000 && ale_block.weight < 0x0020_0000,
        "ALE block weight {:#x} keeps primary exceptions escaping",
        ale_block.weight
    );
    let pkt_block = out
        .iter()
        .find(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
        .unwrap();
    // Within each layer, every permit outranks that layer's block.
    for p in out
        .iter()
        .filter(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::AleAuthConnectV4)
    {
        assert!(p.weight > ale_block.weight);
    }
    for p in out
        .iter()
        .filter(|f| f.action == WfpAction::Permit && f.layer == WfpLayerKey::OutboundTransportV4)
    {
        assert!(p.weight > pkt_block.weight);
    }
    for f in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
    {
        assert_eq!(f.user_sid.as_deref(), Some("S"));
    }
    for f in out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::OutboundTransportV4)
    {
        assert_eq!(f.user_sid, None);
    }
}

#[test]
fn fail_closed_mode_b_other_off_emits_named_packet_blocks_no_permit_unselected() {
    // Everything except "Other": ALE block (TCP/UDP) + named packet blocks
    // (ICMP/IGMP/GRE/ESP). No block-all, so no permit-unselected.
    let protos = KillSwitchProtocols {
        other: false,
        ..KillSwitchProtocols::ALL
    };
    let out = fail_closed_block_all_filters("S", &FailClosedExemptions::default(), protos);
    let pkt_blocks: Vec<u8> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
        .filter_map(|f| f.ip_protocol)
        .collect();
    assert_eq!(pkt_blocks.len(), 4, "ICMP/IGMP/GRE/ESP each get a block");
    assert!(pkt_blocks.contains(&PROTO_ICMP));
    assert!(pkt_blocks.contains(&PROTO_ESP));
    assert_eq!(
        out.iter()
            .filter(|f| f.action == WfpAction::Permit
                && f.layer == WfpLayerKey::OutboundTransportV4)
            .filter(|f| f.ip_protocol.is_some())
            .count(),
        0,
        "no permit-unselected without a block-all"
    );
}

#[test]
fn fail_closed_uncheck_icmp_leaves_icmp_unblocked() {
    // All except ICMP. The packet layer emits only named per-protocol
    // blocks — unchecking ICMP simply means NO ICMP
    // block exists (ping escapes because nothing matches it), and there is
    // never a protocol-agnostic block-all for a permit to outrank.
    let protos = KillSwitchProtocols {
        icmp: false,
        ..KillSwitchProtocols::ALL
    };
    let out = fail_closed_block_all_filters("S", &FailClosedExemptions::default(), protos);
    assert!(
        !out.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4
                && f.action == WfpAction::Block
                && f.ip_protocol.is_none()
        }),
        "no protocol-agnostic packet block-all"
    );
    assert!(
        !out.iter().any(|f| {
            f.layer == WfpLayerKey::OutboundTransportV4 && f.ip_protocol == Some(PROTO_ICMP)
        }),
        "unchecked ICMP gets no packet filter at all — it simply flows"
    );
    // The other named protocols are still individually blocked.
    let named: Vec<u8> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block && f.layer == WfpLayerKey::OutboundTransportV4)
        .filter_map(|f| f.ip_protocol)
        .collect();
    assert_eq!(named.len(), 3, "IGMP/GRE/ESP blocks remain");
}

#[test]
fn fail_closed_mode_b_arms_without_server_ips() {
    // Unlike the catch-all, fail-closed must still cut everything even with
    // NO server exemption (reconnection then needs the user to toggle off).
    let out = fail_closed_block_all_filters(
        "S",
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    // ALE: loopback+link-local+broadcast+local-network-control + block = 5.
    // Packet: same 4 exemptions + 4 named protocol blocks = 8. IPv6: V6 ALE
    // (loopback+link-local+link-local-multicast+block = 4) + V6 transport
    // (3 exemptions + 3 protocol blocks = 6) = 10. Total 23.
    assert_eq!(out.len(), 23);
    assert_eq!(
        out.iter().filter(|f| f.action == WfpAction::Block).count(),
        9,
        "V4 ALE + 4 named V4 packet + V6 ALE + 3 named V6 transport"
    );
}

/// A network can hand out a more specific route for a rule host through the
/// main link (a DHCP classless static route). The leak guard never reads the
/// route table: the host is blocked on every interface, and permitted above that
/// block only while the flow leaves through the additional link, so a planted
/// route ends in the block instead of on the main link.
#[test]
fn a_planted_route_for_a_rule_host_meets_the_block_not_the_main_link() {
    const SECONDARY: u64 = 0x2222;
    let host = Ipv4Addr::new(203, 0, 113, 77);
    let out = kill_switch_filters(
        "S",
        &[IpAddr::V4(host)],
        SECONDARY,
        KillSwitchProtocols::ALL,
    );
    let names_host =
        |f: &&WfpFilterSpec| f.remote_ip == Some(host) || f.remote_ip_set.contains(&host);
    let ale = |f: &&WfpFilterSpec| f.layer == WfpLayerKey::AleAuthConnectV4;

    let blocks: Vec<_> = out
        .iter()
        .filter(names_host)
        .filter(ale)
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    assert!(
        !blocks.is_empty(),
        "no connect-layer block for the rule host"
    );
    assert!(
        blocks.iter().all(|f| f.local_interface_luid.is_none()),
        "the block must hold whatever interface a route picks"
    );
    let permits: Vec<_> = out
        .iter()
        .filter(names_host)
        .filter(ale)
        .filter(|f| f.action == WfpAction::Permit)
        .collect();
    assert!(
        !permits.is_empty(),
        "no connect-layer permit for the rule host"
    );
    for permit in &permits {
        assert_eq!(permit.local_interface_luid, Some(SECONDARY));
        assert!(blocks.iter().all(|b| permit.weight > b.weight));
    }
}
