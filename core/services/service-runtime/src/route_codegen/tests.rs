use super::*;
use crate::app_observation_lookup::MockAppObservationLookup;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_domain::canonical::{CanonicalAppMatch, CanonicalRule};
use nrr_domain::RuleId;

/// No application has been observed connecting anywhere — the state every
/// address-rule test runs in.
fn no_apps() -> MockAppObservationLookup {
    MockAppObservationLookup::new()
}

fn app_rule(id: &str, pattern: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled: true,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact(pattern.to_string()),
            include_child_processes: false,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

#[test]
fn app_only_rule_routes_every_observed_destination() {
    let cache = MockFqdnCacheLookup::new();
    let apps = MockAppObservationLookup::new();
    apps.set_ips(
        "messenger.exe",
        vec![ip(23, 10, 20, 153), ip(23, 10, 20, 137)],
    );
    let rs = ruleset(vec![app_rule("R-app", "messenger.exe")]);

    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &apps,
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    let mut dests: Vec<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    dests.sort();
    assert_eq!(dests, vec![ip(23, 10, 20, 137), ip(23, 10, 20, 153)]);
    assert!(out
        .routes
        .iter()
        .all(|r| r.prefix_length == 32 && r.interface_index == target().interface_index));
    assert!(out.diagnostics.is_empty());
}

/// The case the census exists for: the browser reached the address an hour
/// before the routed application ever touched it. Pinning it would have
/// taken the browser's traffic into the tunnel with it.
#[test]
fn app_only_rule_skips_a_destination_another_process_already_uses() {
    let cache = MockFqdnCacheLookup::new();
    let apps = MockAppObservationLookup::new();
    apps.set_ips(
        "assistant.exe",
        vec![ip(203, 0, 113, 68), ip(203, 0, 113, 9)],
    );
    apps.set_used_outside(ip(203, 0, 113, 68));
    let rs = ruleset(vec![app_rule("R-app", "assistant.exe")]);

    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &apps,
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    let dests: Vec<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, vec![ip(203, 0, 113, 9)]);
    assert!(matches!(
        out.diagnostics.as_slice(),
        [RouteCodegenDiagnostic::AppRuleDestinationUsedByOtherProcess { ip: shared, app, .. }]
            if *shared == ip(203, 0, 113, 68) && app == "assistant.exe"
    ));
}

#[test]
fn app_only_rule_without_observations_diagnoses_and_routes_nothing() {
    let cache = MockFqdnCacheLookup::new();
    let rs = ruleset(vec![app_rule("R-app", "messenger.exe")]);

    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    assert!(out.routes.is_empty());
    assert!(matches!(
        out.diagnostics.as_slice(),
        [RouteCodegenDiagnostic::AppRuleUnobserved { app, .. }] if app == "messenger.exe"
    ));
}

#[test]
fn app_only_rule_skips_destinations_the_shared_address_policy_declined() {
    let cache = MockFqdnCacheLookup::new();
    let apps = MockAppObservationLookup::new();
    apps.set_ips("messenger.exe", vec![ip(8, 8, 8, 8), ip(23, 10, 20, 137)]);
    let rs = ruleset(vec![app_rule("R-app", "messenger.exe")]);
    let denied: HashSet<Ipv4Addr> = [ip(8, 8, 8, 8)].into_iter().collect();

    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &apps,
        &denied,
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    let dests: Vec<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, vec![ip(23, 10, 20, 137)]);
}

fn target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        gateway_v6: None,
        interface_index: 7,
    }
}

/// The same tunnel, on a network that carries IPv6.
fn v6_capable_target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway_v6: Some("fe80::1".parse().expect("literal")),
        ..target()
    }
}

fn rule(id: &str, enabled: bool, m: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.to_string()),
        enabled,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn ruleset(rules: Vec<CanonicalRule>) -> CanonicalRuleSet {
    CanonicalRuleSet::from_rules(rules)
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

/// The live case (26.08): `*.search.example` on the main link,
/// `docs.search.example` on the additional one, one address serving both.
/// The tunnel pin used to take translate.search.example with it, and the site
/// was dead in every browser while both rules were honoured individually.
#[test]
fn a_shared_address_is_not_pinned_into_the_tunnel() {
    let shared = ip(23, 10, 20, 161);
    let only_theirs = ip(23, 10, 20, 150);
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("translate.search.example", vec![shared]);
    cache.set_ips("docs.search.example", vec![shared, only_theirs]);
    let book = CanonicalRuleBook {
        primary: ruleset(vec![rule(
            "p1",
            true,
            CanonicalAddressMatch::SuffixDomain("search.example".into()),
        )]),
        secondary: ruleset(vec![rule(
            "s1",
            true,
            CanonicalAddressMatch::ExactFqdn("docs.search.example".into()),
        )]),
    };
    let ownership = crate::address_ownership::AddressOwnership::resolve(&book, &cache);

    let out = generate_secondary_routes(
        &book.secondary,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &ownership,
        crate::address_ownership::Link::Additional,
    );

    let dests: Vec<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, vec![only_theirs], "the shared address must stay put");
    assert!(
        out.diagnostics.iter().any(|d| matches!(
            d,
            RouteCodegenDiagnostic::AddressClaimedByMainLink { rule_id, ip, count }
                if rule_id == "s1" && *ip == shared && *count == 1
        )),
        "{:?}",
        out.diagnostics
    );
}

/// The main link is never the one held back: its own rules are what the
/// gate protects, and mode B carves them back off the tunnel through this
/// same function.
#[test]
fn the_main_links_own_rules_are_never_held_back() {
    let shared = ip(23, 10, 20, 161);
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("translate.search.example", vec![shared]);
    cache.set_ips("docs.search.example", vec![shared]);
    let book = CanonicalRuleBook {
        primary: ruleset(vec![rule(
            "p1",
            true,
            CanonicalAddressMatch::SuffixDomain("search.example".into()),
        )]),
        secondary: ruleset(vec![rule(
            "s1",
            true,
            CanonicalAddressMatch::ExactFqdn("docs.search.example".into()),
        )]),
    };
    let ownership = crate::address_ownership::AddressOwnership::resolve(&book, &cache);

    let out = generate_secondary_routes(
        &book.primary,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &ownership,
        crate::address_ownership::Link::Main,
    );

    assert_eq!(
        out.routes
            .iter()
            .filter_map(|r| match r.destination {
                IpAddr::V4(d) => Some(d),
                IpAddr::V6(_) => None,
            })
            .collect::<Vec<_>>(),
        vec![shared]
    );
}

#[test]
fn exact_ip_emits_one_host_route_via_secondary() {
    let cache = MockFqdnCacheLookup::new();
    let rs = ruleset(vec![rule(
        "r-ip",
        true,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(23, 10, 20, 138))),
    )]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert_eq!(out.routes.len(), 1);
    let r = &out.routes[0];
    assert_eq!(r.destination, ip(23, 10, 20, 138));
    assert_eq!(r.prefix_length, 32);
    assert_eq!(r.next_hop, ip(10, 0, 0, 1));
    assert_eq!(r.interface_index, 7);
    assert!(r.is_ours);
    assert!(out.diagnostics.is_empty());
}

#[test]
fn disabled_rule_is_skipped() {
    let cache = MockFqdnCacheLookup::new();
    let rs = ruleset(vec![rule(
        "r-off",
        false,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(1, 1, 1, 1))),
    )]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert!(out.routes.is_empty());
}

#[test]
fn block_action_rule_produces_no_route() {
    let cache = MockFqdnCacheLookup::new();
    let mut blocked = rule(
        "r-block",
        true,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(203, 0, 113, 5))),
    );
    blocked.action = nrr_domain::RuleAction::Block;
    let rs = ruleset(vec![blocked]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    // A dropped destination gets no /32 route — the WFP block enforces it.
    assert!(out.routes.is_empty());
}

#[test]
fn exact_fqdn_warm_cache_routes_each_ip_cold_cache_diagnoses() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("api.example.com", vec![ip(20, 0, 0, 1), ip(20, 0, 0, 2)]);
    let rs = ruleset(vec![
        rule(
            "r-warm",
            true,
            CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
        ),
        rule(
            "r-cold",
            true,
            CanonicalAddressMatch::ExactFqdn("cold.example.com".into()),
        ),
    ]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    let dests: BTreeSet<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, BTreeSet::from([ip(20, 0, 0, 1), ip(20, 0, 0, 2)]));
    assert!(out
            .diagnostics
            .iter()
            .any(|d| matches!(d, RouteCodegenDiagnostic::HostnameUnresolved { hostname, .. } if hostname == "cold.example.com")));
}

#[test]
fn suffix_and_zone_fan_out_to_cached_subdomain_ips() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("a.corp.example", vec![ip(30, 0, 0, 1)]);
    cache.set_ips("b.corp.example", vec![ip(30, 0, 0, 2)]);
    // A host under a different suffix must NOT leak in.
    cache.set_ips("x.other.example", vec![ip(99, 0, 0, 9)]);

    let suffix_rules = ruleset(vec![rule(
        "r-suffix",
        true,
        CanonicalAddressMatch::SuffixDomain("corp.example".into()),
    )]);
    let out = generate_secondary_routes(
        &suffix_rules,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    let dests: BTreeSet<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, BTreeSet::from([ip(30, 0, 0, 1), ip(30, 0, 0, 2)]));

    // Zone uses the same fan-out.
    let zone_rules = ruleset(vec![rule(
        "r-zone",
        true,
        CanonicalAddressMatch::Zone("example".into()),
    )]);
    let out2 = generate_secondary_routes(
        &zone_rules,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert!(out2.routes.iter().any(|r| r.destination == ip(99, 0, 0, 9)));
}

#[test]
fn suffix_routes_its_apex_while_a_zone_never_routes_its_bare_label() {
    //  — `*.corp.example` covers "corp.example" itself, so the
    // apex gets a `/32`. A zone rule keeps ignoring its own bare label,
    // otherwise a host literally named "example" would be swept in.
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("corp.example", vec![ip(30, 0, 0, 7)]);
    cache.set_ips("a.corp.example", vec![ip(30, 0, 0, 1)]);
    cache.set_ips("example", vec![ip(88, 0, 0, 8)]);

    let suffix_rules = ruleset(vec![rule(
        "r-suffix",
        true,
        CanonicalAddressMatch::SuffixDomain("corp.example".into()),
    )]);
    let out = generate_secondary_routes(
        &suffix_rules,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    let dests: BTreeSet<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, BTreeSet::from([ip(30, 0, 0, 7), ip(30, 0, 0, 1)]));

    let zone_rules = ruleset(vec![rule(
        "r-zone",
        true,
        CanonicalAddressMatch::Zone("example".into()),
    )]);
    let out2 = generate_secondary_routes(
        &zone_rules,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert!(
        !out2.routes.iter().any(|r| r.destination == ip(88, 0, 0, 8)),
        "the bare zone label must not be routed"
    );
}

#[test]
fn empty_suffix_emits_diagnostic_no_route() {
    let cache = MockFqdnCacheLookup::new();
    let rs = ruleset(vec![rule(
        "r-empty",
        true,
        CanonicalAddressMatch::SuffixDomain("nothing.cached".into()),
    )]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert!(out.routes.is_empty());
    assert!(out
        .diagnostics
        .iter()
        .any(|d| matches!(d, RouteCodegenDiagnostic::SuffixEmpty { .. })));
}

#[test]
fn loopback_and_unspecified_destinations_are_not_routed() {
    let cache = MockFqdnCacheLookup::new();
    // An ad-blocking hosts file pins the domain to loopback → the cache
    // holds only 127.0.0.1, so the ExactFqdn rule must produce NO route.
    cache.set_ips("app.example", vec![ip(127, 0, 0, 1)]);
    // A mixed resolution (loopback + a real public IP) must route ONLY
    // the routable IP.
    cache.set_ips(
        "mixed.example.com",
        vec![ip(127, 0, 0, 1), ip(23, 10, 20, 138)],
    );
    let rs = ruleset(vec![
        rule(
            "r-loop-ip",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(127, 0, 0, 1))),
        ),
        rule(
            "r-unspec-ip",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(0, 0, 0, 0))),
        ),
        rule(
            "r-loop-fqdn",
            true,
            CanonicalAddressMatch::ExactFqdn("app.example".into()),
        ),
        rule(
            "r-mixed",
            true,
            CanonicalAddressMatch::ExactFqdn("mixed.example.com".into()),
        ),
    ]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    // Only the public IP survives; loopback + unspecified are dropped and
    // the loopback-only FQDN yields nothing.
    let dests: BTreeSet<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, BTreeSet::from([ip(23, 10, 20, 138)]));
}

#[test]
fn duplicate_destination_across_rules_is_routed_once() {
    let cache = MockFqdnCacheLookup::new();
    let rs = ruleset(vec![
        rule(
            "r1",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(40, 0, 0, 1))),
        ),
        rule(
            "r2",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(40, 0, 0, 1))),
        ),
    ]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert_eq!(out.routes.len(), 1, "same destination must route once");
}

#[test]
fn combined_app_and_address_rule_is_not_routed_in_free() {
    // A rule with BOTH an app condition and an address is block-only in
    // Free — it must NOT produce a route (routing the address would
    // ignore the app scoping and over-route every process).
    use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern};
    let cache = MockFqdnCacheLookup::new();
    let combined = CanonicalRule {
        id: RuleId("r-app-ip".into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(50, 0, 0, 1)))),
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact("chrome.exe".into()),
            include_child_processes: true,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    };
    let rs = ruleset(vec![combined]);
    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );
    assert!(
        out.routes.is_empty(),
        "combined app+address rule must not route the address globally"
    );
    assert!(out.diagnostics.iter().any(|d| matches!(
        d,
        RouteCodegenDiagnostic::AppRuleAddressAndAppNotRouted { .. }
    )));
}

// ── mode-aware generate_routes (block 16.18.vpn) ──

/// Startup orphan adoption recognises our leftovers by metric plus shape.
/// Its shape list is derived from the overlay constants — this is the other
/// end: every route any mode actually emits must be recognised, so a mode
/// that grows a new shape fails here instead of leaving that shape orphaned
/// in the table after a crash.
#[test]
fn every_shape_the_codegen_emits_is_one_adoption_recognises() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_addresses(
        "news.example",
        vec![
            IpAddr::V4(ip(198, 51, 100, 7)),
            IpAddr::V6("2001:db8::7".parse().expect("literal")),
        ],
    );
    let apps = MockAppObservationLookup::new();
    apps.set_ips("assistant.exe", vec![ip(203, 0, 113, 9)]);
    let rb = book(
        vec![rule(
            "R-main",
            true,
            CanonicalAddressMatch::ExactFqdn("news.example".to_string()),
        )],
        vec![
            rule(
                "R-sec",
                true,
                CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(1, 1, 1, 1))),
            ),
            app_rule("R-app", "assistant.exe"),
        ],
    );
    let primary = SecondaryRouteTarget {
        gateway: ip(192, 168, 1, 1),
        gateway_v6: Some("2001:db8:ffff::1".parse().expect("literal")),
        interface_index: 12,
    };

    for mode in [
        RouteBehaviorMode::PreferPrimary,
        RouteBehaviorMode::PreferSecondaryWhenAvailable,
        RouteBehaviorMode::StrictSecondaryFailClosed,
    ] {
        for primary_opt in [None, Some(&primary)] {
            let out = generate_routes(
                mode,
                &rb,
                primary_opt,
                &v6_capable_target(),
                &cache,
                &apps,
                &std::collections::HashSet::new(),
                crate::address_ownership::ZoneVsIpOrder::default(),
                &[],
            );
            for route in &out.routes {
                assert!(
                        is_owned_shape(route.destination, route.prefix_length),
                        "{mode:?} emits /{} but orphan adoption would not recognise it:                          a crash leaves that route steering traffic into a dead tunnel",
                        route.prefix_length,
                    );
                assert_eq!(
                    route.metric, SECONDARY_ROUTE_METRIC,
                    "adoption also keys on the metric",
                );
            }
        }
    }
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

/// The regression: an application routed over the additional link reaches
/// a site the user put on the MAIN link by name. The destination is learned
/// from that first blocked attempt, and a `/32` pin would then take the
/// address away from every other process on the machine — the browser
/// included. Address rules outrank application rules; the pin must not
/// appear.
#[test]
fn mode_a_app_observation_never_pins_an_address_the_main_link_claims() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("news.example", vec![ip(203, 0, 113, 68)]);
    let apps = MockAppObservationLookup::new();
    apps.set_ips(
        "assistant.exe",
        vec![ip(203, 0, 113, 68), ip(203, 0, 113, 9)],
    );
    let rb = book(
        vec![rule(
            "R-main",
            true,
            CanonicalAddressMatch::ExactFqdn("news.example".to_string()),
        )],
        vec![app_rule("R-app", "assistant.exe")],
    );

    let out = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &rb,
        None,
        &target(),
        &cache,
        &apps,
        &std::collections::HashSet::new(),
        crate::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );

    let dests: Vec<Ipv4Addr> = out
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(dests, vec![ip(203, 0, 113, 9)], "only the unclaimed one");
    // `PrimaryExceptionsUnavailable` rides along (no primary target here),
    // so look for the one that matters rather than matching the whole slice.
    assert!(out.diagnostics.iter().any(|d| matches!(
        d,
        RouteCodegenDiagnostic::AppRuleDestinationClaimedByMainLink { ip: claimed, app, .. }
            if *claimed == ip(203, 0, 113, 68) && app == "assistant.exe"
    )));
}

/// A main-link rule can only defend addresses it actually resolves to, and
/// a suffix rule defends its whole cached fan-out.
#[test]
fn address_rule_ips_expands_names_and_ignores_app_and_block_rules() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("news.example", vec![ip(10, 0, 0, 1)]);
    cache.set_ips("cdn.news.example", vec![ip(10, 0, 0, 2)]);
    let mut blocked = rule(
        "R-block",
        true,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(10, 0, 0, 3))),
    );
    blocked.action = nrr_domain::RuleAction::Block;
    let mut disabled = rule(
        "R-off",
        false,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(10, 0, 0, 4))),
    );
    disabled.enabled = false;
    let rs = ruleset(vec![
        rule(
            "R-suffix",
            true,
            CanonicalAddressMatch::SuffixDomain("news.example".to_string()),
        ),
        rule(
            "R-ip",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(10, 0, 0, 5))),
        ),
        app_rule("R-app", "assistant.exe"),
        blocked,
        disabled,
    ]);

    let claimed = address_rule_ips(&rs, &cache);

    assert_eq!(
        claimed,
        HashSet::from([ip(10, 0, 0, 1), ip(10, 0, 0, 2), ip(10, 0, 0, 5)])
    );
}

#[test]
fn mode_a_prefer_primary_emits_secondary_host_routes_no_overlay() {
    let cache = MockFqdnCacheLookup::new();
    let rb = book(
        vec![rule(
            "p",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(8, 8, 8, 8))),
        )],
        vec![rule(
            "s",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(1, 1, 1, 1))),
        )],
    );
    let out = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &rb,
        None,
        &target(),
        &cache,
        &no_apps(),
        &std::collections::HashSet::new(),
        crate::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );
    // No /1 overlay in mode A; only the secondary rule's /32 (primary rule
    // is irrelevant — default already rides primary).
    assert_eq!(out.routes.len(), 1);
    assert_eq!(out.routes[0].destination, ip(1, 1, 1, 1));
    assert_eq!(out.routes[0].prefix_length, 32);
    assert_eq!(out.routes[0].interface_index, 7); // secondary ifindex
}

#[test]
fn the_counter_overlay_is_one_bit_longer_than_whatever_the_tunnel_installed() {
    let ip = |a, b, c, d| Ipv4Addr::new(a, b, c, d);
    // No visible catch-alls → the classic four /2.
    assert_eq!(counter_overlay_for(&[]), COUNTER_OVERLAY.to_vec());
    // A redirect-gateway /1 pair → the same four /2.
    assert_eq!(
        counter_overlay_for(&[(ip(0, 0, 0, 0), 1), (ip(128, 0, 0, 0), 1)]),
        COUNTER_OVERLAY.to_vec()
    );
    // swiftvpn over WireGuard: a redirect SET. Against it the /2s lost —
    // `64.0.0.0/2` and `128.0.0.0/2` tie on length at a better metric and
    // the rest are longer — so every non-rule connection rode the tunnel.
    // Each prefix gets its two halves, one bit longer.
    let set = [
        (ip(0, 0, 0, 0), 5),
        (ip(8, 0, 0, 0), 7),
        (ip(64, 0, 0, 0), 2),
        (ip(128, 0, 0, 0), 2),
        (ip(192, 0, 0, 0), 9),
    ];
    let got = counter_overlay_for(&set);
    for expected in [
        (ip(0, 0, 0, 0), 6),
        (ip(4, 0, 0, 0), 6),
        (ip(8, 0, 0, 0), 8),
        (ip(9, 0, 0, 0), 8),
        (ip(64, 0, 0, 0), 3),
        (ip(96, 0, 0, 0), 3),
        (ip(128, 0, 0, 0), 3),
        (ip(160, 0, 0, 0), 3),
        (ip(192, 0, 0, 0), 10),
        (ip(192, 64, 0, 0), 10),
    ] {
        assert!(got.contains(&expected), "missing {expected:?} in {got:?}");
    }
    assert_eq!(got.len(), 10);
    // A tunnel that owns the whole default on-link → two /1 via primary.
    assert_eq!(
        counter_overlay_for(&[(ip(0, 0, 0, 0), 0)]),
        vec![(ip(0, 0, 0, 0), 1), (ip(128, 0, 0, 0), 1)]
    );
}

#[test]
fn tunnel_catch_alls_are_the_wide_unicast_routes_on_the_tunnel_that_are_not_ours() {
    let r = |d: [u8; 4], n: u8, ifx: u32, ours: bool| RouteEntry {
        destination: IpAddr::V4(Ipv4Addr::from(d)),
        prefix_length: n,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        interface_index: ifx,
        metric: 0,
        is_ours: ours,
        table: nrr_platform_api::RouteTableRef::Main,
    };
    let table = vec![
        r([64, 0, 0, 0], 2, 66, false),
        r([192, 0, 0, 0], 9, 66, false),
        r([224, 0, 0, 0], 3, 66, false), // multicast: every interface has it
        r([10, 88, 0, 191], 32, 66, false), // the tunnel's own address
        r([10, 200, 0, 0], 16, 66, false), // a corporate split-tunnel network
        r([23, 10, 20, 78], 32, 66, true), // our rule route
        r([0, 0, 0, 0], 0, 19, false),   // the primary's default
    ];
    assert_eq!(
        tunnel_catch_all_prefixes(&table, 66),
        vec![
            (Ipv4Addr::new(64, 0, 0, 0), 2),
            (Ipv4Addr::new(192, 0, 0, 0), 9)
        ]
    );
}

#[test]
fn mode_a_with_primary_adds_counter_overlay_via_primary() {
    let cache = MockFqdnCacheLookup::new();
    let rb = book(
        vec![], // primary rules irrelevant — the /2 counter-overlay covers all non-secondary
        vec![rule(
            "s",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(1, 1, 1, 1))),
        )], // foreign → secondary
    );
    let primary = SecondaryRouteTarget {
        gateway: ip(192, 168, 1, 1),
        gateway_v6: None,
        interface_index: 12,
    };
    let out = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &rb,
        Some(&primary),
        &target(),
        &cache,
        &no_apps(),
        &std::collections::HashSet::new(),
        crate::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );
    // Counter-overlay: four /2 via the primary NIC (ifindex 12) — these
    // out-specific a redirect VPN's /1 so non-rule traffic rides primary.
    let co: Vec<_> = out.routes.iter().filter(|r| r.prefix_length == 2).collect();
    assert_eq!(co.len(), 4);
    assert!(co
        .iter()
        .all(|r| r.interface_index == 12 && r.next_hop == ip(192, 168, 1, 1)));
    let dests: BTreeSet<Ipv4Addr> = co
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    assert_eq!(
        dests,
        BTreeSet::from([
            ip(0, 0, 0, 0),
            ip(64, 0, 0, 0),
            ip(128, 0, 0, 0),
            ip(192, 0, 0, 0)
        ])
    );
    // Foreign /32 stays via the secondary (VPN, ifindex 7) — more specific
    // than the /2, so it wins by longest-prefix.
    let f = out
        .routes
        .iter()
        .find(|r| r.destination == ip(1, 1, 1, 1))
        .expect("secondary /32 route");
    assert_eq!(f.prefix_length, 32);
    assert_eq!(f.interface_index, 7);
    // No /1 overlay in mode A.
    assert!(!out.routes.iter().any(|r| r.prefix_length == 1));
}

#[test]
fn mode_b_owns_overlay_via_secondary_and_pulls_primary_exceptions() {
    let cache = MockFqdnCacheLookup::new();
    let rb = book(
        vec![rule(
            "p",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(8, 8, 8, 8))),
        )],
        vec![],
    );
    let primary = SecondaryRouteTarget {
        gateway: ip(192, 168, 1, 1),
        gateway_v6: None,
        interface_index: 12,
    };
    let out = generate_routes(
        RouteBehaviorMode::PreferSecondaryWhenAvailable,
        &rb,
        Some(&primary),
        &target(),
        &cache,
        &no_apps(),
        &std::collections::HashSet::new(),
        crate::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );
    // Overlay 0.0.0.0/1 + 128.0.0.0/1 via the secondary (ifindex 7).
    let overlay: Vec<_> = out.routes.iter().filter(|r| r.prefix_length == 1).collect();
    assert_eq!(overlay.len(), 2);
    assert!(overlay.iter().all(|r| r.interface_index == 7));
    assert!(overlay.iter().any(|r| r.destination == ip(0, 0, 0, 0)));
    assert!(overlay.iter().any(|r| r.destination == ip(128, 0, 0, 0)));
    // Exception: primary rule 8.8.8.8/32 via the PRIMARY NIC (ifindex 12).
    let exc = out
        .routes
        .iter()
        .find(|r| r.destination == ip(8, 8, 8, 8))
        .expect("primary exception route");
    assert_eq!(exc.prefix_length, 32);
    assert_eq!(exc.interface_index, 12);
    assert_eq!(exc.next_hop, ip(192, 168, 1, 1));
}

#[test]
fn mode_b_without_primary_target_keeps_overlay_and_diagnoses() {
    let cache = MockFqdnCacheLookup::new();
    let rb = book(
        vec![rule(
            "p",
            true,
            CanonicalAddressMatch::ExactIp(IpAddr::V4(ip(8, 8, 8, 8))),
        )],
        vec![],
    );
    let out = generate_routes(
        RouteBehaviorMode::StrictSecondaryFailClosed,
        &rb,
        None,
        &target(),
        &cache,
        &no_apps(),
        &std::collections::HashSet::new(),
        crate::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );
    // Only the overlay survives (no exceptions without a primary target).
    assert_eq!(out.routes.len(), 2);
    assert!(out.routes.iter().all(|r| r.prefix_length == 1));
    assert!(out
        .diagnostics
        .iter()
        .any(|d| matches!(d, RouteCodegenDiagnostic::PrimaryExceptionsUnavailable)));
}

#[test]
fn dns_via_secondary_routes_pin_each_resolver_to_the_secondary() {
    let servers = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)];
    let routes = dns_via_secondary_routes(&servers, &target());
    assert_eq!(routes.len(), 2);
    for (route, expected) in routes.iter().zip(servers.iter()) {
        assert_eq!(route.destination, *expected);
        // A /32 is what makes the source-bound query socket actually leave
        // over the tunnel; anything wider would not out-specific the
        // default route.
        assert_eq!(route.prefix_length, 32);
        assert_eq!(route.interface_index, target().interface_index);
        assert_eq!(route.next_hop, target().gateway);
        assert!(route.is_ours);
    }
}

#[test]
fn dns_via_secondary_routes_skip_non_routable_servers() {
    let servers = [Ipv4Addr::LOCALHOST, Ipv4Addr::UNSPECIFIED];
    assert!(dns_via_secondary_routes(&servers, &target()).is_empty());
}

// ── IPv6 host routes ─────────────────────────────────────────────────

/// A rule host's IPv6 addresses are steered like its IPv4 ones — through
/// the tunnel's own v6 next hop, as `/128`.
#[test]
fn a_rule_hosts_v6_addresses_are_routed_through_the_tunnels_v6_next_hop() {
    let v6: std::net::Ipv6Addr = "2001:db8::7".parse().expect("literal");
    let cache = MockFqdnCacheLookup::new();
    cache.set_addresses(
        "news.example",
        vec![IpAddr::V4(ip(198, 51, 100, 7)), IpAddr::V6(v6)],
    );
    let rs = ruleset(vec![rule(
        "R-sec",
        true,
        CanonicalAddressMatch::ExactFqdn("news.example".to_string()),
    )]);

    let out = generate_secondary_routes(
        &rs,
        &v6_capable_target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    let routed = out
        .routes
        .iter()
        .find(|r| r.destination == IpAddr::V6(v6))
        .expect("the host's v6 address must be steered too");
    assert_eq!(routed.prefix_length, 128, "a v6 host route is a /128");
    assert_eq!(
        routed.next_hop,
        IpAddr::V6("fe80::1".parse().expect("literal")),
        "the v6 route must take the link's own v6 next hop",
    );
    assert_eq!(routed.metric, SECONDARY_ROUTE_METRIC);
    assert!(routed.is_ours);
}

/// A tunnel with no IPv6 way out gets no `/128`: that route would attract
/// traffic to a link that cannot deliver it, and the user reads the hang
/// as a broken site. The kill-switch pin blocks the address instead.
#[test]
fn a_tunnel_without_a_v6_next_hop_gets_no_v6_route() {
    let v6: std::net::Ipv6Addr = "2001:db8::7".parse().expect("literal");
    let cache = MockFqdnCacheLookup::new();
    cache.set_addresses(
        "news.example",
        vec![IpAddr::V4(ip(198, 51, 100, 7)), IpAddr::V6(v6)],
    );
    let rs = ruleset(vec![rule(
        "R-sec",
        true,
        CanonicalAddressMatch::ExactFqdn("news.example".to_string()),
    )]);

    let out = generate_secondary_routes(
        &rs,
        &target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    assert!(
        out.routes.iter().all(|r| r.destination.is_ipv4()),
        "a /128 through a link with no IPv6 is a black hole",
    );
    assert_eq!(out.routes.len(), 1, "the v4 half is routed as before");
}

/// The scopes that never leave the link are never routed, in either
/// family — the v6 half of the hosts-file guard.
#[test]
fn link_scoped_v6_destinations_are_never_routed() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_addresses(
        "news.example",
        vec![
            IpAddr::V6("::1".parse().expect("literal")),
            IpAddr::V6("fe80::5".parse().expect("literal")),
            IpAddr::V6("ff02::fb".parse().expect("literal")),
        ],
    );
    let rs = ruleset(vec![rule(
        "R-sec",
        true,
        CanonicalAddressMatch::ExactFqdn("news.example".to_string()),
    )]);

    let out = generate_secondary_routes(
        &rs,
        &v6_capable_target(),
        &cache,
        &no_apps(),
        &HashSet::new(),
        &crate::address_ownership::AddressOwnership::default(),
        crate::address_ownership::Link::Additional,
    );

    assert!(out.routes.is_empty());
}
