use super::*;

/// A VPN client that renamed only the connection is the common case; the
/// driver description stays generic, so both names have to be read.
#[test]
fn a_renamed_connection_still_reads_as_a_personal_tunnel() {
    let mut tun = adapter("tap", 7, true, true, None);
    tun.description = "TAP-Windows Adapter V9".into();
    tun.friendly_name = "swiftvpn VPN OpenVPN Adapter".into();
    assert_eq!(
        personal_tunnel_name(&[adapter("wifi", 3, true, true, Some([192, 168, 0, 1])), tun]),
        Some("swiftvpn VPN OpenVPN Adapter".to_string())
    );
}

/// A corporate client belongs to an employer; telling that user to make it
/// their additional route would be the product guessing at IT policy.
#[test]
fn a_corporate_client_raises_no_offer() {
    let mut tun = adapter("fort", 8, true, true, None);
    tun.friendly_name = "FortiClient VPN".into();
    tun.description = "FortiClient Virtual Ethernet Adapter".into();
    assert_eq!(personal_tunnel_name(&[tun]), None);
}

/// An installed-but-disconnected client is not a tunnel the user is
/// waiting on.
#[test]
fn a_tunnel_that_is_down_raises_no_offer() {
    let mut tun = adapter("tap", 9, false, false, None);
    tun.friendly_name = "Mullvad VPN".into();
    assert_eq!(personal_tunnel_name(&[tun]), None);
}

fn route_entry(
    dest: [u8; 4],
    prefix: u8,
    next_hop: [u8; 4],
    ifindex: u32,
    metric: u32,
) -> RouteEntry {
    RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(dest)),
        prefix_length: prefix,
        next_hop: IpAddr::V4(Ipv4Addr::from(next_hop)),
        interface_index: ifindex,
        metric,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    }
}

#[test]
fn derives_tunnel_next_hop_from_redirect_gateway_split_routes() {
    // Mirrors a live swiftvpn OpenVPN table: split-default via the
    // peer 10.91.192.1, no adapter gateway, on ifindex 78.
    let routes = vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([10, 91, 193, 99], 32, [0, 0, 0, 0], 78, 256), // on-link → ignored
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25),    // other ifindex → ignored
    ];
    assert_eq!(
        derive_secondary_next_hop(&routes, 78),
        Some(Ipv4Addr::new(10, 91, 192, 1))
    );
    // No default-style route on an unrelated ifindex → None.
    assert_eq!(derive_secondary_next_hop(&routes, 999), None);
}

#[test]
fn derive_prefers_real_default_over_split_halves() {
    let routes = vec![
        route_entry([0, 0, 0, 0], 1, [10, 0, 0, 1], 5, 1), // /1 split half
        route_entry([0, 0, 0, 0], 0, [10, 0, 0, 9], 5, 50), // real /0 default — wins despite higher metric
    ];
    assert_eq!(
        derive_secondary_next_hop(&routes, 5),
        Some(Ipv4Addr::new(10, 0, 0, 9))
    );
}

#[test]
fn derive_ignores_on_link_and_loopback_but_falls_back_to_gateway_style_routes() {
    // A narrow on-link subnet and a loopback row can never name a peer. (A
    // WIDE on-link set is a different story — `interface_rows` covers it.)
    let dead_ends = vec![
        route_entry([10, 0, 0, 0], 8, [0, 0, 0, 0], 5, 1), // on-link (unspecified next-hop)
        route_entry([0, 0, 0, 0], 0, [127, 0, 0, 1], 5, 1), // loopback next-hop
    ];
    assert_eq!(derive_secondary_next_hop(&dead_ends, 5), None);
    //  — a non-default gateway-style route IS a last resort:
    // on a point-to-point tunnel it names the same single peer the
    // stripped catch-alls did.
    let with_host_route = vec![
        route_entry([10, 0, 0, 0], 8, [10, 0, 0, 1], 5, 1),
        route_entry([10, 1, 0, 0], 16, [0, 0, 0, 0], 5, 1),
    ];
    assert_eq!(
        derive_secondary_next_hop(&with_host_route, 5),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
}

#[test]
fn derive_primary_target_picks_lowest_metric_default_off_secondary() {
    let routes = vec![
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // real default on eth (ifx 12)
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),  // VPN /1 half → wrong prefix
        route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1),  // VPN /0 on secondary → excluded
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 254], 12, 5), // lower-metric default → wins
    ];
    let t = derive_primary_target(&routes, 78).expect("primary derived from OS default");
    assert_eq!(t.interface_index, 12);
    assert_eq!(t.gateway, Ipv4Addr::new(192, 168, 1, 254));
}

#[test]
fn derive_primary_target_none_when_only_secondary_has_default() {
    // The VPN replaced /0 itself; nothing left to derive → None (caller warns).
    let routes = vec![route_entry([0, 0, 0, 0], 0, [10, 91, 192, 1], 78, 1)];
    assert!(derive_primary_target(&routes, 78).is_none());
}

#[test]
fn recompute_mode_a_emits_counter_overlay_via_derived_primary() {
    // The footgun: user binds ONLY the secondary (VPN), picks "direct"
    // (mode A). The /2 counter-overlay (so unmatched → real link) needs a
    // primary; we derive it from the OS default route. Without this fix,
    // unmatched traffic silently rode the VPN's redirect.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let vpn_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 0, [192, 168, 1, 1], 12, 25), // OS default on eth
    ]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 23, 10, 20, 138)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &vpn_id); // ONLY secondary bound
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();

    let table = api.get_ip_forward_table().unwrap();
    let counter: Vec<_> = table.iter().filter(|r| r.prefix_length == 2).collect();
    assert_eq!(
        counter.len(),
        4,
        "four /2 counter-overlay routes must be installed via the derived primary"
    );
    assert!(
        counter
            .iter()
            .all(|r| r.interface_index == 12 && r.next_hop == Ipv4Addr::new(192, 168, 1, 1)),
        "counter-overlay must route via the derived primary gateway, not the secondary"
    );
}

#[test]
fn recompute_active_routes_via_derived_next_hop_for_gatewayless_vpn() {
    // End-to-end: a gateway-less VPN adapter must still route —
    // resolve_target derives the tunnel peer from the route table and the
    // /32 overlay is installed via it.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, None); // up, IPv4, NO gateway
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 23, 10, 20, 138)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.added, 1, "the /32 overlay must be installed");

    let table = api.get_ip_forward_table().unwrap();
    let ours = table
        .iter()
        .find(|r| r.destination == Ipv4Addr::new(23, 10, 20, 138))
        .expect("our /32 overlay must be present");
    assert_eq!(
        ours.next_hop,
        Ipv4Addr::new(10, 91, 192, 1),
        "must use the derived tunnel next-hop, not a (missing) adapter gateway"
    );
    assert_eq!(ours.interface_index, 78);
}

#[test]
fn cache_keeps_routes_when_vpn_catch_all_vanishes() {
    // Add-only world (the C2 strip is disabled): if the VPN's catch-all
    // routes briefly vanish — e.g. a reconnect blip — derivation fails, but
    // the cached next-hop keeps our /32 routes alive instead of tearing them
    // down. Guards the gateway-less-VPN next-hop cache.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, None); // up, IPv4, NO gateway
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    api.set_route_table(vec![
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
        route_entry([128, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 23, 10, 20, 138)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    // Cycle 1: derive the peer from the VPN's /1 (cached) + install the /32.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert!(
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .any(|r| r.destination == Ipv4Addr::new(23, 10, 20, 138)),
        "our /32 installed in cycle 1"
    );

    // The VPN's catch-all routes vanish (reconnect blip) — only our /32 left.
    api.set_route_table(vec![route_entry(
        [23, 10, 20, 138],
        32,
        [10, 91, 192, 1],
        78,
        5,
    )]);

    // Cycle 2: derivation fails (no catch-all) → cache fallback keeps the /32.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert!(
        api.get_ip_forward_table()
            .unwrap()
            .iter()
            .any(|r| r.destination == Ipv4Addr::new(23, 10, 20, 138)),
        "our /32 survives via the cached next-hop (NOT cleared)"
    );
}

#[test]
fn resolve_secondary_luid_returns_luid_for_bound_usable_secondary() {
    // the coordinator hands the WFP
    // orchestrator the secondary interface LUID to pin its egress
    // condition to.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let bound_id = vpn.stable_id();
    api.set_adapter_infos(vec![vpn]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &bound_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    assert_eq!(
        coord.resolve_secondary_luid("S-IVANOV"),
        Some(nrr_platform_api::windows_api::mock_luid_for_index(78)),
        "must resolve the bound secondary's ifindex to its LUID",
    );
}

#[test]
fn resolve_secondary_luid_none_when_no_usable_secondary() {
    // No secondary bound at all → None (fail-open: no kill-switch).
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
    assert_eq!(coord.resolve_secondary_luid("S-NOBODY"), None);
}

#[test]
fn resolve_egress_source_ips_returns_the_adapters_own_addresses() {
    // The fake-IP relay binds its dials to these; each role must yield the
    // resolved adapter's OWN unicast address, and a down secondary must
    // yield None (the relay then refuses instead of leaking).
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
    assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(secondary, Some(Ipv4Addr::new(192, 168, 1, 50)));

    // The secondary goes down → its source disappears, the primary stays.
    let vpn_down = adapter("swiftvpnvpn", 78, false, true, Some([10, 0, 0, 1]));
    let eth_up = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    api.set_adapter_infos(vec![vpn_down, eth_up]);
    let (primary, secondary) = coord.resolve_egress_source_ips("S-IVANOV");
    assert_eq!(primary, Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(secondary, None);
}

#[test]
fn kill_switch_exemptions_resolves_luid_servers_and_subnets() {
    // the coordinator derives the catch-all
    // exemptions: the secondary LUID, the VPN server IP (bootstrap host
    // route via the primary gateway), and the primary's connected subnet.
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, 5), // VPN server bootstrap via eth gw
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),     // primary connected subnet
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),      // VPN redirect half
    ]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    let ex = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve when secondary + primary are usable");
    assert_eq!(
        ex.secondary_luid,
        nrr_platform_api::windows_api::mock_luid_for_index(78)
    );
    assert_eq!(ex.bootstrap_server_ips, vec![Ipv4Addr::new(203, 0, 113, 7)]);
    assert_eq!(ex.local_subnets, vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]);
}

/// Mode B pulls primary-bound rules back to the primary NIC as `/32`
/// exceptions — which is byte-for-byte the shape of a VPN bootstrap host
/// route. Collected as "server IPs" they were exempted from the block-all
/// permanently, and cached, so they outlived the rule that made them.
#[test]
fn our_own_exception_routes_are_not_mistaken_for_vpn_server_ips() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    let ours = route_entry([198, 51, 100, 5], 32, [192, 168, 1, 1], 12, 5);
    api.set_route_table(vec![
        route_entry([203, 0, 113, 7], 32, [192, 168, 1, 1], 12, 5), // the real bootstrap route
        ours.clone(),                                               // our mode-B exception
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

    let before = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve");
    assert!(
        before
            .bootstrap_server_ips
            .contains(&Ipv4Addr::new(198, 51, 100, 5)),
        "fixture check: unowned, it looks like a server IP"
    );

    coord.reconciler.adopt_owned(vec![ours]);
    let after = coord
        .kill_switch_exemptions("S-IVANOV")
        .expect("exemptions resolve");
    assert_eq!(
        after.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)],
        "our own route must not become a permanent hole in the block-all"
    );
}

/// An empty route table and an unreadable one must not resolve to the same
/// value: armed on the empty reading, the kill-switch would exempt no LAN,
/// no DHCP and no printers — and say nothing about why.
#[test]
fn an_unreadable_route_table_keeps_the_kill_switch_off() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);
    assert!(
        coord.kill_switch_exemptions("S-IVANOV").is_some(),
        "the fixture itself must resolve"
    );

    api.set_route_table_read_error(Some("enumeration failed"));
    assert!(
        coord.kill_switch_exemptions("S-IVANOV").is_none(),
        "an unknown set of local subnets must not arm a kill-switch"
    );
}

/// The fail-closed path cannot decline — the block-all is armed either way —
/// so it falls back to what the link was last seen with rather than cutting
/// the user's own network.
#[test]
fn fail_closed_falls_back_to_the_last_known_local_subnets() {
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![
        route_entry([192, 168, 1, 0], 24, [0, 0, 0, 0], 12, 5),
        route_entry([0, 0, 0, 0], 1, [10, 91, 192, 1], 78, 1),
    ]);
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::new(FakeRules::new()), policy);

    let warm = coord.fail_closed_exemptions("S-IVANOV");
    assert_eq!(
        warm.local_subnets,
        vec![(Ipv4Addr::new(192, 168, 1, 0), 24)]
    );

    api.set_route_table_read_error(Some("enumeration failed"));
    let degraded = coord.fail_closed_exemptions("S-IVANOV");
    assert_eq!(
        degraded.local_subnets,
        vec![(Ipv4Addr::new(192, 168, 1, 0), 24)],
        "the block-all must keep the LAN it knew about"
    );
}

#[test]
fn kill_switch_exemptions_cache_keeps_server_ip_after_bootstrap_route_vanishes() {
    // The VPN client drops the bootstrap route while disconnected; the
    // last-known server IP must survive (else reconnection deadlocks).
    let api = Arc::new(MockWindowsApi::new());
    let vpn = adapter("swiftvpnvpn", 78, true, true, Some([10, 0, 0, 1]));
    let eth = adapter("eth0", 12, true, true, Some([192, 168, 1, 1]));
    let vpn_id = vpn.stable_id();
    let eth_id = eth.stable_id();
    api.set_adapter_infos(vec![vpn, eth]);
    api.set_route_table(vec![route_entry(
        [203, 0, 113, 7],
        32,
        [192, 168, 1, 1],
        12,
        5,
    )]);
    let rules = Arc::new(FakeRules::new());
    let policy = Arc::new(FakePolicy::new());
    policy.bind_primary("S-IVANOV", &eth_id);
    policy.bind_secondary("S-IVANOV", &vpn_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    // Cycle 1: server IP present → cached.
    let ex1 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
    assert_eq!(
        ex1.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)]
    );

    // Bootstrap route vanishes (VPN disconnected).
    api.set_route_table(vec![]);

    // Cycle 2: live table empty → cache fallback keeps the server IP.
    let ex2 = coord.kill_switch_exemptions("S-IVANOV").unwrap();
    assert_eq!(
        ex2.bootstrap_server_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7)],
        "cached server IP must survive a bootstrap-route blip"
    );
}

#[test]
fn description_matches_display_name_version_robust_and_symmetric() {
    // Live description carries an extra version token vs the saved name.
    assert!(description_matches_display_name(
        "SwiftVPN 3.0 OpenVPN Adapter",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    // regression: the SAVED name carries the version token and the
    // live adapter dropped it — the "every other day" heal failure. The old
    // directional subset returned false here; symmetric containment heals it.
    assert!(description_matches_display_name(
        "swiftvpn VPN OpenVPN Adapter",
        "SwiftVPN 3.0 OpenVPN Adapter",
    ));
    // Both sides versioned, different versions → same family.
    assert!(description_matches_display_name(
        "swiftvpn VPN 4.1 OpenVPN Adapter",
        "SwiftVPN 3.0 OpenVPN Adapter",
    ));
    // Survives a version bump (saved has no version).
    assert!(description_matches_display_name(
        "swiftvpn VPN 4.1 OpenVPN Adapter",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    // Case-insensitive.
    assert!(description_matches_display_name(
        "SWIFTVPN vpn openvpn ADAPTER",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    // Different adapter → no match, both directions.
    assert!(!description_matches_display_name(
        "Intel(R) Ethernet Connection (2) I219-V",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    assert!(!description_matches_display_name(
        "swiftvpn VPN OpenVPN Adapter",
        "Intel(R) Ethernet Connection (2) I219-V",
    ));
    // Empty / whitespace-only display_name never matches.
    assert!(!description_matches_display_name("anything at all", "   "));
    // A name reduced to ONLY a version token has an empty core → no match
    // (never heal to an adapter whose family is unidentifiable).
    assert!(!description_matches_display_name("3.0", "swiftvpn VPN"));
    // The vendor spells the same brand with an underscore on its WireGuard
    // adapter and with spaces on its OpenVPN one. Treating "swiftvpn_VPN"
    // as one opaque token left a live, connected tunnel unrecognised while the
    // bound TAP device sat broken, and the route stayed fail-closed.
    assert!(description_matches_display_name(
        "swiftvpn_VPN",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    // Category words alone are not evidence: an adapter called just "VPN" is a
    // token-subset of every VPN name there is.
    assert!(!description_matches_display_name(
        "VPN",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    assert!(!description_matches_display_name(
        "VPN Tunnel",
        "swiftvpn VPN OpenVPN Adapter",
    ));
    // A different vendor's tunnel never answers to ours, even though both
    // carry the category words.
    assert!(!description_matches_display_name(
        "othervendor_VPN Adapter",
        "swiftvpn VPN OpenVPN Adapter",
    ));
}

#[test]
fn a_renamed_connection_on_a_stock_driver_still_answers_to_its_saved_name() {
    // The Windows 11 case: swiftvpn renames the CONNECTION but ships the
    // stock TAP driver, so the saved name shares no token with the driver
    // description and only the friendly name can identify the adapter.
    let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
    vpn.description = "TAP-Windows Adapter V9".into();
    vpn.friendly_name = "swiftvpn VPN OpenVPN Adapter".into();

    assert!(!description_matches_display_name(
        &vpn.description,
        "swiftvpn VPN OpenVPN Adapter"
    ));
    assert!(adapter_answers_to_saved_name(
        &vpn,
        "swiftvpn VPN OpenVPN Adapter"
    ));
    // The stored name follows the connection, so the GUI keeps the label
    // the user recognises.
    assert_eq!(preferred_display_name(&vpn), "swiftvpn VPN OpenVPN Adapter");

    // An unrelated adapter must not be adopted through either name.
    let mut wifi = adapter("wifi", 17, true, true, Some([192, 168, 0, 1]));
    wifi.description = "Intel(R) Dual Band Wireless-AC 7265".into();
    wifi.friendly_name = "Wi-Fi".into();
    assert!(!adapter_answers_to_saved_name(
        &wifi,
        "swiftvpn VPN OpenVPN Adapter"
    ));
}

#[test]
fn a_blank_friendly_name_falls_back_to_the_driver_description() {
    let mut vpn = adapter("tap", 9, true, true, Some([10, 88, 0, 1]));
    vpn.description = "TAP-Windows Adapter V9".into();
    vpn.friendly_name = "   ".into();
    assert_eq!(preferred_display_name(&vpn), "TAP-Windows Adapter V9");
    assert!(adapter_answers_to_saved_name(
        &vpn,
        "TAP-Windows Adapter V9"
    ));
}

#[test]
fn recompute_active_resolves_target_and_routes_for_the_active_user() {
    // End-to-end through the wiring entry point: active SID → its
    // secondary binding → live adapter → target → routes.
    let api = Arc::new(MockWindowsApi::new());
    let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
    let sec_id = sec.stable_id();
    api.set_adapter_infos(vec![sec.clone()]);

    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &sec_id);

    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);
    let delta = coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    assert_eq!(delta.added, 1);
    let table = api.get_ip_forward_table().unwrap();
    let r = table
        .iter()
        .find(|r| r.destination == Ipv4Addr::new(1, 1, 1, 1))
        .unwrap();
    assert_eq!(r.interface_index, 9);
    assert_eq!(r.next_hop, Ipv4Addr::new(10, 0, 0, 1));
}

#[test]
fn adopt_orphans_picks_our_signature_then_recompute_purges_unwanted() {
    // Two of our /32 @metric5 orphans + one foreign route survive a
    // crash. Adoption claims only the two; a recompute that desires just
    // .1 deletes .2 but leaves the foreign route untouched.
    let api = Arc::new(MockWindowsApi::new());
    let ours_a = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        prefix_length: 32,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        interface_index: 9,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    let ours_b = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ..ours_a.clone()
    };
    // Foreign: a /24 at a different metric — must NOT be adopted.
    let foreign = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 0)),
        prefix_length: 24,
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        interface_index: 3,
        metric: 256,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    api.set_route_table(vec![ours_a.clone(), ours_b, foreign.clone()]);

    let sec = adapter("vpn", 9, true, true, Some([10, 0, 0, 1]));
    let sec_id = sec.stable_id();
    api.set_adapter_infos(vec![sec]);
    let rules = Arc::new(FakeRules::new());
    rules.set_secondary(
        "S-IVANOV",
        CanonicalRuleSet::from_rules(vec![ip_rule("r1", 1, 1, 1, 1)]),
    );
    let policy = Arc::new(FakePolicy::new());
    policy.bind_secondary("S-IVANOV", &sec_id);
    let coord = coordinator_with_policy(Arc::clone(&api), Arc::clone(&rules), policy);

    coord.adopt_orphans_from_table();
    assert_eq!(coord.owned_count(), 2, "both /32 @5 orphans adopted");

    // Active user wants only .1 → .2 is purged, foreign stays.
    coord.recompute_active(&["S-IVANOV".to_string()]).unwrap();
    let dests = table_dests(&api);
    assert!(
        dests.contains(&Ipv4Addr::new(1, 1, 1, 1)),
        "desired route kept"
    );
    assert!(!dests.contains(&Ipv4Addr::new(2, 2, 2, 2)), "orphan purged");
    assert!(
        dests.contains(&Ipv4Addr::new(8, 8, 8, 0)),
        "foreign route untouched"
    );
}

#[test]
fn adopt_orphans_claims_mode_a_counter_overlay_not_just_slash32() {
    // Regression: a crash/kill (not a graceful stop) can strand the mode-A
    // `/2` counter-overlay (metric 5, on the primary NIC) in the OS table.
    // Adoption must claim it alongside the `/32` host routes, or the `/2`
    // lingers forever and keeps forcing all non-rule traffic to the primary
    // after the owning service is gone.
    let api = Arc::new(MockWindowsApi::new());
    // Our /2 counter-overlay half @metric5 (primary NIC ifindex 12).
    let overlay = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        prefix_length: 2,
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        interface_index: 12,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    // Our /32 secondary host route @metric5.
    let host = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        prefix_length: 32,
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        interface_index: 9,
        metric: 5,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    // Foreign /2 at a different metric — must NOT be adopted.
    let foreign_overlay = RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::new(64, 0, 0, 0)),
        prefix_length: 2,
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
        interface_index: 12,
        metric: 256,
        is_ours: false,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    api.set_route_table(vec![overlay, host, foreign_overlay]);

    let rules = Arc::new(FakeRules::new());
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));

    coord.adopt_orphans_from_table();
    assert_eq!(
        coord.owned_count(),
        2,
        "the /2 counter-overlay and the /32 host route are both adopted; the foreign /2 @256 is not"
    );
}

#[test]
fn recompute_active_with_no_active_user_clears_table() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new());
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let delta = coord.recompute_active(&[]).unwrap();
    assert!(delta.is_noop());
    assert!(table_dests(&api).is_empty());
}

#[test]
fn principal_with_no_rules_clears_routes_via_read_through_miss() {
    let api = Arc::new(MockWindowsApi::new());
    let rules = Arc::new(FakeRules::new()); // nothing set, no baseline
    let coord = coordinator(Arc::clone(&api), Arc::clone(&rules));
    let delta = coord
        .recompute_for("S-UNKNOWN", &res(Some(target())))
        .unwrap();
    assert!(delta.is_noop());
    assert!(table_dests(&api).is_empty());
}
