use super::*;

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

/// `*vpn*` misses an entire family of corporate clients: "ViPNet" has no `vpn`
/// substring (v-i-p-n-e-t), and neither do S-Terra or Continent. On such a
/// machine the tunnel's own transport fell under fail-closed and we cut it —
/// the user loses the corporate network and blames the product that did it.
///
/// The check is on the MATCH, not on the list's contents: a rename that keeps
/// the family covered passes, and dropping the family fails.
#[test]
fn the_corporate_clients_without_vpn_in_their_name_are_exempt() {
    fn exempted(exe: &str) -> bool {
        DEFAULT_VPN_EXEMPT_PATTERNS
            .iter()
            .any(|pattern| nrr_platform_api::app_path_resolver::glob_match(pattern, exe))
    }
    for exe in [
        "vipnet client.exe",
        "itcs-vipnet.exe",
        "s-terra client.exe",
        "sterraclient.exe",
        "continent-ap.exe",
    ] {
        assert!(exempted(exe), "{exe} would be cut by our own fail-closed");
    }
    // And the prefix stays a prefix: an ordinary word inside a name is not a
    // reason to hand an application unconditional egress.
    assert!(!exempted("transcontinental-sync.exe"));
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
/// the outage never ends.
#[test]
fn a_recognised_client_lends_its_install_tree_to_the_exemption() {
    use nrr_platform_api::app_path_resolver::MockAppPathResolver;
    use std::path::PathBuf;

    let client = r"C:\Program Files\vendor vpn\vendor vpn.exe";
    // The nested directories are placeholders; only the file names matter —
    // one must match the built-in `*vpn*` glob, the other deliberately must not.
    let resolver = MockAppPathResolver::new().with_siblings(
        client,
        vec![
            PathBuf::from(r"C:\Program Files\vendor vpn\dir-b\openvpn.exe"),
            PathBuf::from(r"C:\Program Files\vendor vpn\dir-c\xray.exe"),
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
        &v4_pins([ip(127, 0, 0, 1), ip(169, 254, 1, 1)]),
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
        &v4_pins([ip(127, 0, 0, 1), ip(203, 0, 113, 5), ip(169, 254, 0, 9)]),
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
        &v4_pins([ip(1, 1, 1, 1), ip(2, 2, 2, 2)]),
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
        &v4_pins([ip(1, 1, 1, 1), ip(2, 2, 2, 2), ip(3, 3, 3, 3)]),
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
        &v4_pins([ip(1, 1, 1, 1), ip(2, 2, 2, 2)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S",
        &v4_pins([ip(1, 1, 1, 1), ip(2, 2, 2, 2)]),
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
        &v4_pins([ip(1, 1, 1, 1)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S-1-5-21-B",
        &v4_pins([ip(1, 1, 1, 1)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert_ne!(a[0].id.raw, b[0].id.raw);
    assert_ne!(a[1].id.raw, b[1].id.raw);
}

#[test]
fn filters_span_ale_and_packet_layers() {
    let out = kill_switch_filters(
        "S",
        &v4_pins([ip(9, 9, 9, 9)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert!(out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
    assert!(out
        .iter()
        .any(|f| f.layer == WfpLayerKey::OutboundTransportV4));
}
