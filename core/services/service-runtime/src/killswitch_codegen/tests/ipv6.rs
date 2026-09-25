use super::*;

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
    // v6 hosts are pinned by the rule codegen's v6 chunks, not here: an IPv4
    // pin must never turn into a V6-layer filter.
    assert!(v6_filters(&kill_switch_filters(
        "S",
        &v4_pins([ip(203, 0, 113, 5)]),
        LUID,
        KillSwitchProtocols::ALL
    ))
    .is_empty());
    assert!(v6_filters(&fail_closed_block_destinations(
        "S",
        &v4_pins([ip(203, 0, 113, 5)]),
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

/// The v6 half of a blanket block has to spare the same things as the v4 half:
/// the tunnel's own endpoint and the LAN. A family cut that spares only the
/// link-scope prefixes is a block on everything the user can reach over IPv6.
#[test]
fn the_v6_block_spares_the_tunnel_endpoint_and_the_local_prefix() {
    let server: std::net::Ipv6Addr = "2001:db8:ffff::7".parse().expect("literal");
    let lan: std::net::Ipv6Addr = "2001:db8:1::".parse().expect("literal");
    let out = catch_all_v6_filters("S", 0x1234, &[server], &[(lan, 64)]);
    for layer in [
        WfpLayerKey::AleAuthConnectV6,
        WfpLayerKey::OutboundIpPacketV6,
    ] {
        assert!(
            out.iter().any(|f| f.layer == layer
                && f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((server, 128))),
            "{layer:?}: the tunnel's own v6 endpoint is blocked, so it can never dial back",
        );
        assert!(
            out.iter().any(|f| f.layer == layer
                && f.action == WfpAction::Permit
                && f.remote_subnet_v6 == Some((lan, 64))),
            "{layer:?}: the v6 LAN is cut along with everything else",
        );
    }
}

/// A v6 destination pins the same way a v4 one does — permit while the flow
/// egresses the tunnel, block otherwise — and lands on the V6 layer. On a
/// tunnel that carries no IPv6 the permit simply never matches, which is the
/// block the rule asked for; it must not become a permit-everything.
#[test]
fn a_v6_destination_gets_its_own_pin_pair_on_the_v6_layer() {
    let out = kill_switch_filters("S", &[v6("2001:db8::5")], LUID, KillSwitchProtocols::ALL);
    let ale: Vec<_> = out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV6)
        .collect();
    assert_eq!(ale.len(), 2, "one permit + one block on the v6 ALE layer");
    let permit = ale
        .iter()
        .find(|f| f.action == WfpAction::Permit)
        .expect("permit half");
    let block = ale
        .iter()
        .find(|f| f.action == WfpAction::Block)
        .expect("block half");
    assert_eq!(permit.local_interface_luid, Some(LUID));
    assert!(block.local_interface_luid.is_none());
    assert!(
        permit.weight > block.weight,
        "the pin must outrank its block"
    );
    assert_eq!(
        permit.remote_ip_set_v6,
        vec!["2001:db8::5"
            .parse::<std::net::Ipv6Addr>()
            .expect("literal")]
    );
    // No v4 filter is invented for a v6 destination.
    assert!(out.iter().all(|f| f.remote_ip_set.is_empty()));
}

/// Loopback and the link-local scopes are never blocked, in either family —
/// the v6 half of the exemption the v4 pin set has always applied.
#[test]
fn the_v6_pin_set_skips_the_scopes_that_must_never_be_cut() {
    let out = kill_switch_filters(
        "S",
        &[v6("::1"), v6("fe80::1"), v6("ff02::fb")],
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert!(
        out.is_empty(),
        "every input was an address that must never be cut"
    );
}
