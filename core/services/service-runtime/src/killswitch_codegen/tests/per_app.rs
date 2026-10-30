use super::*;

// ── Per-app kill-switch ────────────────────────────────────

/// One app routed over the tunnel, the tunnel drops, and
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
    // ALE only (no per-app packet layer): one permit + one block PER FAMILY.
    // The v4-only pair let a dual-stack site take the program's IPv6 out of
    // the main link, the tunnel up or down.
    assert_eq!(out.len(), 4);
    for layer in [WfpLayerKey::AleAuthConnectV4, WfpLayerKey::AleAuthConnectV6] {
        let of = |action| {
            out.iter()
                .filter(|f| f.layer == layer && f.action == action)
                .count()
        };
        assert_eq!(of(WfpAction::Permit), 1, "{layer:?}");
        assert_eq!(of(WfpAction::Block), 1, "{layer:?}");
    }
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
    //
    // In BOTH families: a tunnel client whose server has an IPv6 address met
    // the v6 block-all with no permit of its own, and under "everything" with
    // the tunnel down could not reconnect.
    let out = primary_app_exempt_filters(
        "S",
        &["ExampleVPN 3.0.exe".to_string(), "*vpn*".to_string()],
    );
    assert_eq!(
        out.len(),
        4,
        "one exempt permit per pattern and family, no block half"
    );
    for pattern in ["ExampleVPN 3.0.exe", "*vpn*"] {
        let layers: Vec<WfpLayerKey> = out
            .iter()
            .filter(|f| f.app_pattern.as_deref() == Some(pattern))
            .map(|f| f.layer)
            .collect();
        assert_eq!(
            layers,
            vec![WfpLayerKey::AleAuthConnectV4, WfpLayerKey::AleAuthConnectV6],
            "{pattern}"
        );
    }
    for f in &out {
        assert_eq!(f.action, WfpAction::Permit);
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
    assert!(out
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV6)
        .all(|f| f.weight > CATCHALL_BLOCK_WEIGHT && f.remote_subnet_v6.is_none()));
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
    // a well-formed unconditional exempt permit (out-of-the-box
    // VPN-bootstrap protection).
    assert!(DEFAULT_VPN_EXEMPT_PATTERNS.contains(&"*vpn*"));
    let pats: Vec<String> = DEFAULT_VPN_EXEMPT_PATTERNS
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let out = primary_app_exempt_filters("S", &pats);
    assert_eq!(out.len(), 2 * DEFAULT_VPN_EXEMPT_PATTERNS.len());
    assert!(out.iter().all(|f| f.action == WfpAction::Permit
        && matches!(
            f.layer,
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
        )
        && f.local_interface_luid.is_none()
        && f.remote_ip.is_none()));
}

#[test]
fn app_kill_switch_never_touches_packet_layer() {
    // ALE_APP_ID is not available at the packet layer — a per-app ICMP gate
    // is impossible, so nothing must land there.
    let out = app_kill_switch_filters("S", &["a.exe".to_string()], LUID, KillSwitchProtocols::ALL);
    assert!(out.iter().all(|f| matches!(
        f.layer,
        WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
    )));
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
    assert_eq!(out.len(), 4, "each app, both families");
    assert!(out.iter().all(|f| f.action == WfpAction::Block
        && matches!(
            f.layer,
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
        )
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
    // (named-only packet layer), all for it.
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
        &v4_pins([ip(198, 51, 100, 1), ip(198, 51, 100, 2)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    // Per CHUNK: 2 ALE + 4×2 named transport.
    let chunks = pack_v4([ip(198, 51, 100, 1), ip(198, 51, 100, 2)]).len();
    assert_eq!(out.len(), chunks * 10);
    for f in &out {
        match f.layer {
            WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6 => {
                assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-XYZ"))
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
fn weights_do_not_collide_within_each_layer() {
    let out = kill_switch_filters(
        "S",
        &v4_pins([
            ip(198, 51, 100, 1),
            ip(198, 51, 100, 2),
            ip(198, 51, 100, 3),
        ]),
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
        &v4_pins([ip(198, 51, 100, 1), ip(198, 51, 100, 2)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S",
        &v4_pins([ip(198, 51, 100, 1), ip(198, 51, 100, 2)]),
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
        &v4_pins([ip(198, 51, 100, 1)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    let b = kill_switch_filters(
        "S-1-5-21-B",
        &v4_pins([ip(198, 51, 100, 1)]),
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
        &v4_pins([ip(198, 51, 100, 9)]),
        LUID,
        KillSwitchProtocols::ALL,
    );
    assert!(out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV4));
    assert!(out
        .iter()
        .any(|f| f.layer == WfpLayerKey::OutboundTransportV4));
}

// ── Programs take all their addresses ──────────────────────────────────────

/// With the setting on the app takes main-named addresses too, so its block
/// must outrank every primary rule permit, and still lose to its own permit
/// while the tunnel is up.
#[test]
fn under_the_takeover_the_app_block_outranks_the_primary_rule_permits() {
    use crate::wfp_bands::{BAND_WIDTH, BASE_PRIMARY};
    let apps = ["helper.exe".to_string(), "other.exe".to_string()];
    let out = app_kill_switch_filters_for("S", &apps, LUID, KillSwitchProtocols::ALL, true);
    let permits: Vec<&WfpFilterSpec> = out
        .iter()
        .filter(|f| f.action == WfpAction::Permit)
        .collect();
    let blocks: Vec<&WfpFilterSpec> = out
        .iter()
        .filter(|f| f.action == WfpAction::Block)
        .collect();
    assert_eq!(blocks.len(), 4, "two apps, both families");
    for block in &blocks {
        assert!(
            block.weight >= BASE_PRIMARY + BAND_WIDTH,
            "the app block must outrank every primary rule permit ({:#x})",
            block.weight
        );
        let own_permit = permits
            .iter()
            .find(|p| p.app_pattern == block.app_pattern && p.layer == block.layer)
            .expect("each app has its permit in each family");
        assert!(
            own_permit.weight > block.weight,
            "the app's own egress-conditional permit must still win while the tunnel is up"
        );
    }
    // The fail-closed twin keeps the same promise with the tunnel unresolved.
    let fc = fail_closed_block_apps_for("S", &apps, KillSwitchProtocols::ALL, true);
    assert!(fc.iter().all(|f| f.weight >= BASE_PRIMARY + BAND_WIDTH));
}

/// Off is today's behaviour, filter for filter.
#[test]
fn without_the_takeover_the_app_pair_is_unchanged() {
    let apps = ["helper.exe".to_string()];
    assert_eq!(
        app_kill_switch_filters_for("S", &apps, LUID, KillSwitchProtocols::ALL, false),
        app_kill_switch_filters("S", &apps, LUID, KillSwitchProtocols::ALL),
    );
    assert_eq!(
        fail_closed_block_apps_for("S", &apps, KillSwitchProtocols::ALL, false),
        fail_closed_block_apps("S", &apps, KillSwitchProtocols::ALL),
    );
    let block = app_kill_switch_filters("S", &apps, LUID, KillSwitchProtocols::ALL)
        .into_iter()
        .find(|f| f.action == WfpAction::Block)
        .expect("the app block exists");
    assert!(block.weight >= APP_KILLSWITCH_BLOCK_BASE && block.weight < RULE_PRIMARY_BAND);
}

/// Switching the setting moves the block to another weight, and a WFP filter
/// is immutable by key: the id has to change with it.
#[test]
fn the_takeover_block_has_its_own_id() {
    let apps = ["helper.exe".to_string()];
    let id_of = |on: bool| {
        app_kill_switch_filters_for("S", &apps, LUID, KillSwitchProtocols::ALL, on)
            .into_iter()
            .find(|f| f.action == WfpAction::Block)
            .expect("the app block exists")
            .id
    };
    assert_ne!(id_of(true), id_of(false));
}

/// Past the window the block keeps the sub-primary weight rather than climb
/// into the app permits above it.
#[test]
fn an_app_past_the_takeover_window_keeps_the_sub_primary_weight() {
    use crate::wfp_bands::{APP_TAKEOVER_MAX_APPS, KILLSWITCH_PERMIT_BASE};
    let last_in = app_block_band(APP_TAKEOVER_MAX_APPS as u64 - 1, true).0;
    assert!(last_in < KILLSWITCH_PERMIT_BASE);
    let past = app_block_band(APP_TAKEOVER_MAX_APPS as u64, true);
    assert_eq!(past, app_block_band(APP_TAKEOVER_MAX_APPS as u64, false));
}

// ── Destinations withdrawn from a pinned app ───────────────────────────────

/// The ALE v4 verdict for `app` connecting to `to` out of `egress`: the
/// highest-weight match wins, a tie goes to the block.
fn app_verdict(filters: &[WfpFilterSpec], app: &str, to: Ipv4Addr, egress: u64) -> WfpAction {
    filters
        .iter()
        .filter(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .filter(|f| f.app_pattern.as_deref().is_none_or(|a| a == app))
        .filter(|f| f.local_interface_luid.is_none_or(|l| l == egress))
        .filter(|f| f.remote_ip_set.is_empty() || f.covers_v4(to))
        .max_by_key(|f| (f.weight, f.action == WfpAction::Block))
        .map_or(WfpAction::Permit, |f| f.action)
}

/// A withdrawn destination may not be relearnt, so the app block held it off
/// the main link for the rest of the session. The permit opens exactly that
/// app to exactly that address, whichever band the block sits in.
#[test]
fn a_withdrawn_destination_opens_on_the_main_link_for_its_app_alone() {
    const MAIN: u64 = 0x0006_0000_0000_0002;
    let withdrawn = ip(149, 154, 167, 51);
    let kept = ip(149, 154, 175, 50);
    let apps = [
        r"C:\Apps\tg.exe".to_string(),
        r"C:\Apps\mail.exe".to_string(),
    ];
    for takeover in [false, true] {
        let mut out =
            app_kill_switch_filters_for("S", &apps, LUID, KillSwitchProtocols::ALL, takeover);
        out.extend(app_withdrawn_permits(
            "S",
            &apps,
            |app| {
                if app == apps[0] {
                    vec![IpAddr::V4(withdrawn)]
                } else {
                    Vec::new()
                }
            },
            LUID,
            KillSwitchProtocols::ALL,
        ));
        assert_eq!(
            app_verdict(&out, &apps[0], withdrawn, MAIN),
            WfpAction::Permit,
            "takeover {takeover}"
        );
        assert_eq!(
            app_verdict(&out, &apps[0], kept, MAIN),
            WfpAction::Block,
            "takeover {takeover}"
        );
        assert_eq!(
            app_verdict(&out, &apps[1], withdrawn, MAIN),
            WfpAction::Block,
            "takeover {takeover}"
        );
        assert_eq!(
            app_verdict(&out, &apps[0], kept, LUID),
            WfpAction::Permit,
            "takeover {takeover}"
        );
    }
}

/// The permit stays below everything that must still bind the app — the
/// user's own Blocks and the exemptions — and needs the pair to exist at all.
#[test]
fn a_withdrawn_permit_loses_to_user_blocks_and_needs_the_pair() {
    use crate::wfp_bands::{APP_EXEMPT_BASE, BASE_BLOCK};
    let apps = ["tg.exe".to_string()];
    let ips = |_: &str| {
        vec![
            IpAddr::V4(ip(149, 154, 167, 51)),
            "2001:db8::51".parse().unwrap(),
        ]
    };
    let out = app_withdrawn_permits("S", &apps, ips, LUID, KillSwitchProtocols::ALL);
    assert_eq!(out.len(), 2, "one permit per family");
    for f in &out {
        assert_eq!(f.action, WfpAction::Permit);
        assert_eq!(f.local_interface_luid, None);
        assert_eq!(f.app_pattern.as_deref(), Some("tg.exe"));
        assert_eq!(f.user_sid.as_deref(), Some("S"));
        assert!(
            f.weight < BASE_BLOCK,
            "a user Block must still bind the app"
        );
        assert!(f.weight < APP_EXEMPT_BASE, "the exemptions stay above it");
    }
    assert!(out.iter().any(|f| f.layer == WfpLayerKey::AleAuthConnectV6));
    assert!(app_withdrawn_permits("S", &apps, ips, 0, KillSwitchProtocols::ALL).is_empty());
    let no_ale = KillSwitchProtocols::from_bits(0);
    assert!(app_withdrawn_permits("S", &apps, ips, LUID, no_ale).is_empty());
}

/// A filter is immutable by key: a new withdrawal must mint a new id, or the
/// add-only install keeps the old set.
#[test]
fn a_new_withdrawal_mints_a_new_permit_id() {
    let apps = ["tg.exe".to_string()];
    let id = |n: u8| {
        app_withdrawn_permits(
            "S",
            &apps,
            |_| (1..=n).map(|d| IpAddr::V4(ip(149, 154, 167, d))).collect(),
            LUID,
            KillSwitchProtocols::ALL,
        )[0]
        .id
    };
    assert_ne!(id(1), id(2));
}
