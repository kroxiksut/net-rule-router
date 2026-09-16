use super::*;

// ── Fail-closed posture ─────────────────────────────────────────────────

#[test]
fn fail_closed_mode_a_blocks_each_protected_dest_at_both_layers() {
    // All protocols: per dest → 1 ALE block (TCP/UDP) + 4 named packet
    // blocks (16.HW-0716: ICMP/IGMP/GRE/ESP, no agnostic block-all).
    let out = fail_closed_block_destinations(
        "S",
        &v4_pins([ip(203, 0, 113, 5), ip(8, 8, 8, 8)]),
        KillSwitchProtocols::ALL,
    );
    let chunks = pack_v4([ip(203, 0, 113, 5), ip(8, 8, 8, 8)]).len();
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
    assert!(out.iter().any(|f| f.covers_v4(ip(8, 8, 8, 8))));
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
    assert!(fail_closed_block_destinations("S", &v4_pins([ip(8, 8, 8, 8)]), none).is_empty());
    assert!(fail_closed_block_all_filters("S", &FailClosedExemptions::default(), none).is_empty());
}

#[test]
fn fail_closed_allow_dns_over_primary_adds_port_scoped_dns_permits() {
    // opt-in: with `allow_dns_over_primary` the block-all set
    // gains port-scoped (remote UDP/TCP 53) ALE permits so name resolution keeps
    // working over the primary link; off (the strict default) it must not.
    let strict = fail_closed_block_all_filters(
        "S",
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    assert!(
        !strict.iter().any(|f| f.remote_port == Some(53)),
        "strict block-all must NOT permit DNS over the primary link"
    );

    let ex = FailClosedExemptions {
        allow_dns_over_primary: true,
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
    assert_eq!(dns.len(), 2, "expected exactly UDP-53 + TCP-53 permits");
    assert!(dns.iter().any(|f| f.ip_protocol == Some(17)), "UDP permit");
    assert!(dns.iter().any(|f| f.ip_protocol == Some(6)), "TCP permit");
    // Port-scoped, not a full-host tunnel: no remote_ip pin.
    assert!(dns.iter().all(|f| f.remote_ip.is_none()));
}

#[test]
fn fail_closed_block_all_permits_known_primary_at_packet_layer_above_block() {
    // a known-primary host earns a
    // packet-layer proto-agnostic permit that outranks the named packet
    // blocks, so ping/ICMP to it survives the block-all (the ya.ru case).
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
    // + V6 packet (4) = 8. Total 25.
    assert_eq!(out.len(), 25);
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
        "no protocol-agnostic packet block-all (16.HW-0716)"
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
    // (loopback+link-local+link-local-multicast+block = 4) + V6 packet (4)
    // = 8. Total 21.
    assert_eq!(out.len(), 21);
    assert_eq!(
        out.iter().filter(|f| f.action == WfpAction::Block).count(),
        7,
        "V4 ALE + 4 named V4 packet + V6 ALE + V6 packet block-all"
    );
}
