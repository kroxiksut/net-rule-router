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
    let out = catch_all_v6_filters("S", LUID);
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
    let unresolved = catch_all_v6_filters("S", 0);
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
        local_subnets: Vec::new(),
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
    assert!(kill_switch_filters("S", &[], LUID, KillSwitchProtocols::ALL).is_empty());
}

#[test]
fn zero_luid_disables_kill_switch() {
    // A bad LUID must fail OPEN — never emit a black-hole Block.
    let out = kill_switch_filters("S", &[ip(203, 0, 113, 5)], 0, KillSwitchProtocols::ALL);
    assert!(out.is_empty(), "zero LUID must produce no filters");
}

#[test]
fn single_destination_emits_ale_pair_plus_packet_pair() {
    // All protocols: 1 dest → ALE permit+block (TCP/UDP) + one packet
    // egress-permit + block per NAMED packet protocol (ICMP/IGMP/GRE/ESP;
    // 16.HW-0716: "Other" no longer adds an agnostic pair) = 2 + 4×2 = 10.
    let out = kill_switch_filters("S", &[ip(203, 0, 113, 5)], LUID, KillSwitchProtocols::ALL);
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
    let out = kill_switch_filters("S", &[ip(8, 8, 8, 8)], LUID, protos);
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
    let out = kill_switch_filters("S", &[ip(8, 8, 8, 8)], LUID, KillSwitchProtocols::ALL);
    let permit = &out[0];
    let block = &out[1];
    assert!(permit.weight > block.weight, "permit must outrank block");
    assert!(
        block.weight > RULE_PRIMARY_BAND,
        "kill-switch block must outrank the rule primary band"
    );
}

// ── Per-app kill-switch ────────────────────────────────────

/// The 23.08 shape: one app routed over the tunnel, the tunnel drops, and
/// the per-process block (which carries no destination condition) takes
/// down sites the user had explicitly put on the MAIN link. The guard is
/// the block's BAND: below the primary rule band, so every primary rule's
/// own permit outranks it — uncapped, unlike the 64-entry rescue permits
/// this ordering replaced (a live session named 521 addresses, rescued 64).
#[test]
fn an_app_block_loses_to_every_primary_rule_permit() {
    let out = app_kill_switch_filters(
        "S",
        &["helper.exe".to_string()],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let block = out
        .iter()
        .find(|f| f.action == WfpAction::Block)
        .expect("the app block exists");
    assert!(
        block.weight < RULE_PRIMARY_BAND,
        "the app block must lose to primary rule permits ({:#x})",
        block.weight
    );
    // The fail-closed twin makes the same promise while the link is
    // unresolved.
    let fc = fail_closed_block_apps("S", &["helper.exe".to_string()], KillSwitchProtocols::ALL);
    assert!(fc.iter().all(|f| f.weight < RULE_PRIMARY_BAND));
}

#[test]
fn app_kill_switch_emits_ale_pair_pinned_to_app_and_luid() {
    let out = app_kill_switch_filters(
        "S",
        &["C:\\Games\\game.exe".to_string()],
        LUID,
        KillSwitchProtocols::ALL,
    );
    // ALE only (no per-app packet layer): exactly one permit + one block.
    assert_eq!(out.len(), 2);
    let permit = &out[0];
    let block = &out[1];
    assert_eq!(permit.action, WfpAction::Permit);
    assert_eq!(permit.layer, WfpLayerKey::AleAuthConnectV4);
    assert_eq!(permit.app_pattern.as_deref(), Some("C:\\Games\\game.exe"));
    assert_eq!(
        permit.local_interface_luid,
        Some(LUID),
        "app permit is egress-conditional on the secondary LUID"
    );
    assert_eq!(
        permit.remote_ip, None,
        "the app pair is keyed on app id, not IP"
    );
    assert_eq!(block.action, WfpAction::Block);
    assert_eq!(block.app_pattern.as_deref(), Some("C:\\Games\\game.exe"));
    assert_eq!(
        block.local_interface_luid, None,
        "app block is unconditional so it fires the instant the secondary adapter drops"
    );
    assert!(permit.weight > block.weight, "permit must outrank block");
    assert!(
        block.weight >= APP_KILLSWITCH_BLOCK_BASE && block.weight < RULE_PRIMARY_BAND,
        "app block must outrank the secondary band (the per-process Permit) but lose to primary rule permits"
    );
}

#[test]
fn primary_app_exempt_emits_unconditional_permit_above_all_bands() {
    // a primary-routed app must be EXEMPT from the kill-switch:
    // one unconditional ALE Permit per pattern, at the exempt band, outranking
    // every block. No interface/IP condition so it permits egress over the
    // primary even while the secondary adapter is down and block-all is engaged.
    let out =
        primary_app_exempt_filters("S", &["SwiftVPN 3.0.exe".to_string(), "*vpn*".to_string()]);
    assert_eq!(out.len(), 2, "one exempt permit per pattern, no block half");
    for f in &out {
        assert_eq!(f.action, WfpAction::Permit);
        assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
        assert_eq!(
            f.local_interface_luid, None,
            "unconditional — allowed over any link, incl. primary"
        );
        assert_eq!(f.remote_ip, None, "keyed on app id, not IP");
        assert!(f.app_pattern.is_some());
        assert!(
            f.weight >= APP_EXEMPT_BASE,
            "exempt permit must sit in the top exempt band"
        );
    }
    assert_eq!(out[0].app_pattern.as_deref(), Some("SwiftVPN 3.0.exe"));
    assert_eq!(out[1].app_pattern.as_deref(), Some("*vpn*"));
}

#[test]
fn primary_app_exempt_empty_input_emits_nothing() {
    assert!(primary_app_exempt_filters("S", &[]).is_empty());
}

#[test]
fn default_vpn_exempt_patterns_present_and_each_emits_an_exempt_permit() {
    // The built-in defaults must include the broad glob and each must produce
    // a well-formed unconditional exempt permit (HW-0712 C4, out-of-the-box
    // VPN-bootstrap protection).
    assert!(DEFAULT_VPN_EXEMPT_PATTERNS.contains(&"*vpn*"));
    let pats: Vec<String> = DEFAULT_VPN_EXEMPT_PATTERNS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let out = primary_app_exempt_filters("S", &pats);
    assert_eq!(out.len(), DEFAULT_VPN_EXEMPT_PATTERNS.len());
    assert!(out.iter().all(|f| f.action == WfpAction::Permit
        && f.layer == WfpLayerKey::AleAuthConnectV4
        && f.local_interface_luid.is_none()
        && f.remote_ip.is_none()));
}

/// The window is not the tunnel. A client that ships its transports as nested
/// executables must have THOSE exempt, or fail-closed blocks the handshake and
/// the outage never ends — the 2026-09-08 shape.
#[test]
fn a_recognised_client_lends_its_install_tree_to_the_exemption() {
    use nrr_platform_api::app_path_resolver::MockAppPathResolver;
    use std::path::PathBuf;

    let client = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    let resolver = MockAppPathResolver::new().with_siblings(
        client,
        vec![
            PathBuf::from(r"C:\Program Files\vendor vpn\OpenVPN\openvpn.exe"),
            PathBuf::from(r"C:\Program Files\vendor vpn\XRay\ExternalBinaries\xray.exe"),
            // Already named as the client — must not be added twice; filter ids
            // are path-derived, so a duplicate is a duplicate filter.
            PathBuf::from(client),
        ],
    );

    let tree = tunnel_client_tree_exempt_paths(&resolver, &[client.to_string()]);

    assert_eq!(
        tree.len(),
        2,
        "the client's own path is not re-added: {tree:?}"
    );
    assert!(tree.iter().any(|p| p.ends_with("openvpn.exe")));
    assert!(
        tree.iter().any(|p| p.ends_with("xray.exe")),
        "a transport matching NO vpn name pattern is exactly what the tree is for: {tree:?}",
    );
    // Positive control on the emitter: each added path becomes a real permit.
    let filters = primary_app_exempt_filters("S", &tree);
    assert_eq!(filters.len(), 2);
    assert!(filters
        .iter()
        .all(|f| f.action == WfpAction::Permit && f.app_pattern.is_some()));
}

#[test]
fn an_unrecognised_app_lends_nothing_and_the_tree_is_capped() {
    use nrr_platform_api::app_path_resolver::MockAppPathResolver;
    use std::path::PathBuf;

    let client = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    let bundle: Vec<PathBuf> = (0..CLIENT_TREE_EXEMPT_CAP + 10)
        .map(|i| PathBuf::from(format!(r"C:\Program Files\vendor vpn\tool{i}.exe")))
        .collect();
    let resolver = MockAppPathResolver::new().with_siblings(client, bundle);

    assert_eq!(
        tunnel_client_tree_exempt_paths(&resolver, &[client.to_string()]).len(),
        CLIENT_TREE_EXEMPT_CAP,
        "a client that ships a toolchain must not decide how many filters we hold",
    );
    assert!(
        tunnel_client_tree_exempt_paths(&resolver, &[]).is_empty(),
        "no recognised client, no tree",
    );
}

#[test]
fn app_kill_switch_never_touches_packet_layer() {
    // ALE_APP_ID is not available at the packet layer — a per-app ICMP gate
    // is impossible, so nothing must land there.
    let out = app_kill_switch_filters("S", &["a.exe".to_string()], LUID, KillSwitchProtocols::ALL);
    assert!(out.iter().all(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
}

#[test]
fn app_kill_switch_zero_luid_fails_open() {
    let out = app_kill_switch_filters("S", &["a.exe".to_string()], 0, KillSwitchProtocols::ALL);
    assert!(
        out.is_empty(),
        "zero LUID must fail open (no per-app filters)"
    );
}

#[test]
fn app_kill_switch_icmp_only_emits_nothing() {
    let protos = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: true,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = app_kill_switch_filters("S", &["a.exe".to_string()], LUID, protos);
    assert!(
        out.is_empty(),
        "no TCP/UDP selected → the ALE-only app kill-switch emits nothing"
    );
}

#[test]
fn fail_closed_block_apps_blocks_each_protected_app() {
    let out = fail_closed_block_apps(
        "S",
        &["a.exe".to_string(), "b.exe".to_string()],
        KillSwitchProtocols::ALL,
    );
    assert_eq!(out.len(), 2);
    assert!(out.iter().all(|f| f.action == WfpAction::Block
        && f.layer == WfpLayerKey::AleAuthConnectV4
        && f.app_pattern.is_some()));
}

#[test]
fn fail_closed_block_apps_icmp_only_emits_nothing() {
    let protos = KillSwitchProtocols {
        tcp: false,
        udp: false,
        icmp: true,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let out = fail_closed_block_apps("S", &["a.exe".to_string()], protos);
    assert!(out.is_empty());
}

#[test]
fn loopback_and_link_local_are_exempt() {
    let out = kill_switch_filters(
        "S",
        &[ip(127, 0, 0, 1), ip(169, 254, 1, 1)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert!(
        out.is_empty(),
        "loopback and link-local must never be kill-switched"
    );
}

#[test]
fn exempt_ips_are_skipped_while_others_are_kept() {
    let out = kill_switch_filters(
        "S",
        &[ip(127, 0, 0, 1), ip(203, 0, 113, 5), ip(169, 254, 0, 9)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    // The one non-exempt IP → ALE pair + 4 named packet pairs = 10 filters
    // (16.HW-0716: named-only packet layer), all for it.
    assert_eq!(out.len(), 10);
    for f in &out {
        assert!(f.covers_v4(ip(203, 0, 113, 5)));
        assert!(!f.covers_v4(ip(127, 0, 0, 1)));
        assert!(!f.covers_v4(ip(169, 254, 0, 9)));
    }
}

#[test]
fn ale_filters_carry_sid_packet_filters_do_not() {
    let out = kill_switch_filters(
        "S-1-5-21-XYZ",
        &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    // Per CHUNK: 2 ALE + 4×2 named transport.
    let chunks = pack_v4([ip(1, 1, 1, 1), ip(2, 2, 2, 2)]).len();
    assert_eq!(out.len(), chunks * 10);
    for f in &out {
        match f.layer {
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-XYZ"))
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
fn weights_do_not_collide_within_each_layer() {
    let out = kill_switch_filters(
        "S",
        &[ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    // Weights only need to be distinct WITHIN a layer (WFP arbitrates per
    // layer); the packet bands deliberately reuse the ALE numeric space.
    for layer in [
        WfpLayerKey::AleAuthConnectV4,
        WfpLayerKey::OutboundTransportV4,
    ] {
        let weights: Vec<u64> = out
            .iter()
            .filter(|f| f.layer == layer)
            .map(|f| f.weight)
            .collect();
        let unique: std::collections::HashSet<u64> = weights.iter().copied().collect();
        assert_eq!(
            unique.len(),
            weights.len(),
            "weights distinct within {layer:?}"
        );
    }
}

#[test]
fn filter_ids_are_deterministic_and_distinct() {
    let a = kill_switch_filters(
        "S",
        &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S",
        &[ip(1, 1, 1, 1), ip(2, 2, 2, 2)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let ids_a: Vec<u64> = a.iter().map(|f| f.id.raw).collect();
    let ids_b: Vec<u64> = b.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids_a, ids_b, "same inputs must yield identical filter ids");
    let unique: std::collections::HashSet<u64> = ids_a.iter().copied().collect();
    assert_eq!(unique.len(), ids_a.len(), "all ids must differ");
}

#[test]
fn different_sids_produce_different_filter_ids() {
    let a = kill_switch_filters(
        "S-1-5-21-A",
        &[ip(1, 1, 1, 1)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S-1-5-21-B",
        &[ip(1, 1, 1, 1)],
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert_ne!(a[0].id.raw, b[0].id.raw);
    assert_ne!(a[1].id.raw, b[1].id.raw);
}

#[test]
fn filters_span_ale_and_packet_layers() {
    let out = kill_switch_filters("S", &[ip(9, 9, 9, 9)], LUID, KillSwitchProtocols::ALL);
    assert!(out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
    assert!(out
        .iter()
        .any(|f| f.layer == WfpLayerKey::OutboundTransportV4));
}

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
        local_subnets: Vec::new(),
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
        local_subnets: Vec::new(),
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

fn full_resolution() -> KillSwitchResolution {
    KillSwitchResolution {
        secondary_luid: LUID,
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
        foreign_tunnel_luids: Vec::new(),
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
    let ips = [ip(203, 0, 113, 5), ip(198, 51, 100, 7)];
    let apps = ["C:\\Apps\\tunnel.exe".to_string()];
    let exemptions = FailClosedExemptions {
        bootstrap_server_ips: vec![ip(203, 0, 113, 7)],
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
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

// ── Fail-closed posture ─────────────────────────────────────────────────

#[test]
fn fail_closed_mode_a_blocks_each_protected_dest_at_both_layers() {
    // All protocols: per dest → 1 ALE block (TCP/UDP) + 4 named packet
    // blocks (16.HW-0716: ICMP/IGMP/GRE/ESP, no agnostic block-all).
    let out = fail_closed_block_destinations(
        "S",
        &[ip(203, 0, 113, 5), ip(8, 8, 8, 8)],
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
        &[ip(127, 0, 0, 1), ip(203, 0, 113, 5)],
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
    let out = fail_closed_block_destinations("S", &[ip(203, 0, 113, 5)], protos);
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
    assert!(fail_closed_block_destinations("S", &[ip(8, 8, 8, 8)], none).is_empty());
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
        local_subnets: vec![(ip(192, 168, 1, 0), 24)],
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

// ── IPv6 catch-all coverage (Free's only IPv6 handling) ─────────────────

/// Every V6 filter emitted by a catch-all: loopback + link-local +
/// link-local-multicast exemption permits over a block-all, at BOTH V6
/// layers.
fn v6_filters(out: &[WfpFilterSpec]) -> Vec<&WfpFilterSpec> {
    out.iter()
        .filter(|f| {
            matches!(
                f.layer,
                WfpLayerKey::AleAuthConnectV6 | WfpLayerKey::OutboundIpPacketV6
            )
        })
        .collect()
}

#[test]
fn catch_all_emits_v6_exemptions_and_block_all_at_both_v6_layers() {
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    for layer in [
        WfpLayerKey::AleAuthConnectV6,
        WfpLayerKey::OutboundIpPacketV6,
    ] {
        let at: Vec<_> = out.iter().filter(|f| f.layer == layer).collect();
        assert_eq!(
            at.len(),
            4,
            "{layer:?}: loopback + link-local + link-local-multicast exemptions + one block-all"
        );
        // ::1/128, fe80::/10 and ff02::/16 exemptions.
        assert!(at.iter().any(|f| f.action == WfpAction::Permit
            && f.remote_subnet_v6 == Some((Ipv6Addr::LOCALHOST, 128))));
        assert!(at.iter().any(|f| f.action == WfpAction::Permit
            && f.remote_subnet_v6 == Some((Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10))));
        // Neighbour discovery, MLD, mDNS and DHCPv6 address the GROUP, so
        // without this one the link's own upkeep is what the cut destroys.
        assert!(at.iter().any(|f| f.action == WfpAction::Permit
            && f.remote_subnet_v6 == Some((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16))));
        // One unconditional block-all.
        let block = at.iter().find(|f| f.action == WfpAction::Block).unwrap();
        assert!(block.remote_ip.is_none());
        assert!(block.remote_subnet.is_none());
        assert!(block.remote_subnet_v6.is_none());
        assert!(block.local_interface_luid.is_none());
        // Every V6 exemption permit must outrank the V6 block-all.
        for permit in at.iter().filter(|f| f.action == WfpAction::Permit) {
            assert!(
                permit.weight > block.weight,
                "V6 exemption must outrank the V6 block-all in {layer:?}"
            );
        }
    }
    // V6 ALE filters are per-SID; V6 packet filters are system-wide.
    for f in v6_filters(&out) {
        match f.layer {
            WfpLayerKey::AleAuthConnectV6 => assert_eq!(f.user_sid.as_deref(), Some("S")),
            WfpLayerKey::OutboundIpPacketV6 => {
                assert_eq!(f.user_sid, None, "V6 packet layer has no ALE_USER_ID")
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn catch_all_v6_coverage_present_even_when_only_tcp_udp_selected() {
    // IPv6 coverage is orthogonal to the V4 protocol mask — the catch-all
    // cuts all IPv6 whenever it fires.
    let tcp_udp = KillSwitchProtocols::from_bits(0x03);
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        tcp_udp,
    );
    assert_eq!(
        v6_filters(&out).len(),
        8,
        "8 V6 filters regardless of V4 mask"
    );
}

#[test]
fn fail_closed_mode_b_emits_v6_coverage() {
    let out = fail_closed_block_all_filters(
        "S",
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    assert_eq!(
        v6_filters(&out).len(),
        8,
        "V6 half present in fail-closed mode B"
    );
}

#[test]
fn per_ip_paths_never_emit_v6() {
    // The per-destination / per-app fail-closed + kill-switch paths stay
    // IPv4-only (selective V6 needs AAAA — not supported). None of them may
    // ever emit a V6-layer filter.
    assert!(v6_filters(&kill_switch_filters(
        "S",
        &[ip(203, 0, 113, 5)],
        LUID,
        KillSwitchProtocols::ALL
    ))
    .is_empty());
    assert!(v6_filters(&fail_closed_block_destinations(
        "S",
        &[ip(203, 0, 113, 5)],
        KillSwitchProtocols::ALL
    ))
    .is_empty());
    assert!(v6_filters(&app_kill_switch_filters(
        "S",
        &["a.exe".to_string()],
        LUID,
        KillSwitchProtocols::ALL,
    ))
    .is_empty());
    assert!(v6_filters(&fail_closed_block_apps(
        "S",
        &["a.exe".to_string()],
        KillSwitchProtocols::ALL
    ))
    .is_empty());
}

#[test]
fn v6_filter_ids_are_distinct_across_layers_and_targets() {
    // The id seed excludes the layer, so ALE/packet twins rely on distinct
    // kind tags. Assert every V6 filter id is unique within a catch-all.
    let out = catch_all_kill_switch_filters(
        "S",
        &full_resolution(),
        &FailClosedExemptions::default(),
        KillSwitchProtocols::ALL,
    );
    let ids: Vec<u64> = v6_filters(&out).iter().map(|f| f.id.raw).collect();
    let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "all V6 filter ids must differ");
}
