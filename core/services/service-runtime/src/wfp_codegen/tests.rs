use super::*;
use crate::app_observation_lookup::MockAppObservationLookup;
use crate::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_domain::canonical::{CanonicalAppMatch, CanonicalAppPattern, CanonicalRuleSet};
use nrr_domain::RuleId;
use nrr_platform_api::types::{WfpAction, WfpLayerKey};
use nrr_platform_api::{AppPathResolver, MockAppPathResolver, NoopAppPathResolver};
use std::path::PathBuf;

// ── Fixture helpers ─────────────────────────────────────────────────────

fn exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactIp(IpAddr::V4(addr))),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn exact_fqdn_rule(id: &str, name: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::ExactFqdn(name.into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn suffix_rule(id: &str, suffix: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::SuffixDomain(suffix.into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn zone_rule(id: &str, zone: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(CanonicalAddressMatch::Zone(zone.into())),
        app_match: None,
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn app_rule(id: &str, process: &str, include_children: bool) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact(process.into()),
            include_child_processes: include_children,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn glob_app_rule(id: &str, glob: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Glob(glob.into()),
            include_child_processes: false,
        }),
        comment: String::new(),
        action: nrr_domain::RuleAction::Route,
        origin: None,
    }
}

fn disabled_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
    let mut r = exact_ip_rule(id, addr);
    r.enabled = false;
    r
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

/// The filter side of the 26.08 case. It has to reach the same verdict as
/// the route side, or the address is routed one way and permitted the
/// other — which is how a destination ends up dead for every process.
#[test]
fn a_shared_address_gets_no_secondary_filter() {
    let shared = Ipv4Addr::new(23, 10, 20, 161);
    let only_theirs = Ipv4Addr::new(23, 10, 20, 150);
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("translate.search.example", vec![shared]);
    cache.set_ips("docs.search.example", vec![shared, only_theirs]);
    let rule_book = book(
        vec![suffix_rule("p1", "search.example")],
        vec![exact_fqdn_rule("s1", "docs.search.example")],
    );
    let out = generate_filters(CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    // The main link's own suffix rule still covers the shared address.
    assert!(out
        .filters
        .iter()
        .any(|f| f.covers_v4(shared) && f.action == WfpAction::Permit));
    // The additional link's rule got its private address and not the shared one.
    assert!(
        !out.secondary_dest_ips.contains(&IpAddr::V4(shared)),
        "{:?}",
        out.secondary_dest_ips
    );
    assert!(out.secondary_dest_ips.contains(&IpAddr::V4(only_theirs)));
    assert!(
        out.diagnostics.iter().any(|d| matches!(
            d,
            CodegenDiagnostic::AddressClaimedByPrimary { rule_id, ip, count }
                if rule_id == "s1" && *ip == shared && *count == 1
        )),
        "{:?}",
        out.diagnostics
    );
}

// ── ExactIp ─────────────────────────────────────────────────────────────

#[test]
fn exact_ip_rule_emits_single_filter_with_remote_ip() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 5))],
        vec![],
    );
    let out = generate_filters(CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(out.filters.len(), 1);
    let f = &out.filters[0];
    assert_eq!(f.action, WfpAction::Permit);
    assert_eq!(f.layer, WfpLayerKey::AleAuthConnectV4);
    assert!(f.covers_v4(Ipv4Addr::new(203, 0, 113, 5)));
    assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-A"));
    assert!(f.app_pattern.is_none());
    assert!(out.diagnostics.is_empty());
}

// ── ExactFqdn ───────────────────────────────────────────────────────────

#[test]
fn exact_fqdn_rule_fans_out_over_cached_ips() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(
        "api.example.com",
        vec![
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(203, 0, 113, 2),
            Ipv4Addr::new(203, 0, 113, 3),
        ],
    );
    let rule_book = book(vec![exact_fqdn_rule("r-1", "api.example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Packed by slot, so the ADDRESSES are the contract and their order is
    // not: `pack_v4` groups by a hash of the address, deliberately
    // independent of the order they arrived in.
    let mut ips: Vec<_> = out.filters.iter().flat_map(destination_ips).collect();
    ips.sort();
    assert_eq!(
        ips,
        vec![
            Ipv4Addr::new(203, 0, 113, 1),
            Ipv4Addr::new(203, 0, 113, 2),
            Ipv4Addr::new(203, 0, 113, 3),
        ]
    );
    assert!(out.diagnostics.is_empty());
}

// ── Behavioral-equivalence characterisation ──────────────────────────
// Ties the neutral behavioral-equivalence oracle
// (`nrr_platform_api::wfp_behavioral`) to the REAL codegen output: the
// current `generate_filters` is deterministic (re-apply = no churn, the
// idempotency the no-hash-gate design relies on) and the oracle accepts it as
// self-equivalent while still telling two different scenarios apart. It
// is checked against this oracle instead of literal weight/id assertions.
#[test]
fn codegen_output_is_deterministic_and_behaviorally_self_equivalent() {
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(
        "api.example.com",
        vec![Ipv4Addr::new(203, 0, 113, 1), Ipv4Addr::new(203, 0, 113, 2)],
    );
    // A mixed scenario: a primary ExactIp permit + a secondary ExactFqdn
    // fan-out — a multi-filter, multi-role output.
    let rule_book = book(
        vec![exact_ip_rule("p-1", Ipv4Addr::new(198, 51, 100, 7))],
        vec![exact_fqdn_rule("s-1", "api.example.com")],
    );
    // Hoisted so the closure below can borrow them (a returned `CodegenInput`
    // cannot reference temporaries created inside the closure).
    let app_obs = MockAppObservationLookup::new();
    let denylist = std::collections::HashSet::new();
    let input = || CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &app_obs,
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    };

    let first = generate_filters(input());
    let second = generate_filters(input());

    // Determinism = re-apply-no-churn: identical filters INCLUDING weight/id
    // (same build → same FNV-1a ids), so a re-apply is a WFP no-op.
    assert_eq!(
        first, second,
        "codegen must be deterministic (re-apply = no churn)"
    );
    // The oracle accepts the real output as self-equivalent (and preserves
    // its own arbitration order).
    assert!(behaviorally_equivalent(&first.filters, &second.filters));
    assert!(arbitration_order_preserved(&first.filters, &second.filters));

    // Teeth on real output: a DIFFERENT scenario is NOT equivalent.
    let other_book = book(
        vec![exact_ip_rule("p-1", Ipv4Addr::new(10, 0, 0, 9))],
        vec![],
    );
    let other = generate_filters(CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &other_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(
        !behaviorally_equivalent(&first.filters, &other.filters),
        "the oracle must distinguish different enforcement"
    );
}

#[test]
fn exact_fqdn_rule_with_cold_cache_emits_diagnostic_no_filter() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![exact_fqdn_rule("r-cold", "uncached.example")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
    assert_eq!(
        out.diagnostics,
        vec![CodegenDiagnostic::HostnameUnresolved {
            rule_id: "r-cold".into(),
            hostname: "uncached.example".into()
        }]
    );
}

// ── SuffixDomain ────────────────────────────────────────────────────────

#[test]
fn suffix_domain_fans_out_over_cached_subdomains_and_their_ips() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("api.example.com", vec![Ipv4Addr::new(1, 1, 1, 1)]);
    cache.set_ips(
        "www.example.com",
        vec![Ipv4Addr::new(2, 2, 2, 2), Ipv4Addr::new(2, 2, 2, 3)],
    );
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // 1 (api) + 2 (www) = 3 filters
    assert_eq!(out.filters.len(), 3);
    let ips: Vec<_> = out.filters.iter().flat_map(destination_ips).collect();
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 3))));
}

#[test]
fn suffix_domain_fan_out_includes_the_apex() {
    //  — `*.example.com` covers "example.com" itself, so the apex
    // must get a filter. Enforcement has to agree with the decision engine
    // here: a matched host with no filter is exactly the silent leak apex
    // coverage exists to close.
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("example.com", vec![Ipv4Addr::new(9, 9, 9, 9)]);
    cache.set_ips("www.example.com", vec![Ipv4Addr::new(2, 2, 2, 2)]);
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let ips: Vec<_> = out.filters.iter().flat_map(destination_ips).collect();
    assert!(
        ips.contains(&IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        "apex IP: {ips:?}"
    );
    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))));
}

#[test]
fn zone_fan_out_still_excludes_the_bare_zone_label() {
    // Zone semantics are untouched: a host literally named "test" is not a
    // member of the zone "test".
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("test", vec![Ipv4Addr::new(9, 9, 9, 9)]);
    cache.set_ips("a.test", vec![Ipv4Addr::new(2, 2, 2, 2)]);
    let rule_book = book(vec![zone_rule("r-zone", "test")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let ips: Vec<_> = out.filters.iter().flat_map(destination_ips).collect();
    assert_eq!(ips, vec![Ipv4Addr::new(2, 2, 2, 2)]);
}

#[test]
fn suffix_domain_with_only_a_cached_apex_still_emits_a_filter() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("example.com", vec![Ipv4Addr::new(9, 9, 9, 9)]);
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(out.filters.len(), 1);
    assert!(out.diagnostics.is_empty());
}

#[test]
fn suffix_domain_with_no_cached_subdomains_emits_diagnostic() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
    assert_eq!(
        out.diagnostics,
        vec![CodegenDiagnostic::SuffixEmpty {
            rule_id: "r-suf".into(),
            suffix: "example.com".into()
        }]
    );
}

#[test]
fn suffix_domain_over_many_hosts_keeps_every_address_inside_one_band() {
    // 300 cached hosts — past the old 256-slot cap. Every host must get a
    // filter (nothing dropped), no truncation diagnostic, and every weight
    // must stay inside this rule's band so the next rule cannot collide.
    let cache = MockFqdnCacheLookup::new();
    let hosts = 300usize;
    for i in 0..hosts {
        cache.set_ips(
            &format!("h{i}.example.com"),
            vec![Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)],
        );
    }
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Packing is why this is now a coverage question rather than a count:
    // 300 hosts fold into a handful of chunk filters, and what must hold is
    // that not one address fell out along the way.
    let covered: std::collections::HashSet<IpAddr> =
        out.filters.iter().flat_map(destination_ips).collect();
    assert_eq!(covered.len(), hosts, "no host may lose its coverage");
    assert!(
        out.filters.len() < hosts,
        "the whole point of packing is fewer filters than addresses: {} vs {hosts}",
        out.filters.len()
    );
    assert!(
        !out.diagnostics
            .iter()
            .any(|d| matches!(d, CodegenDiagnostic::SuffixTruncated { .. })),
        "300 hosts are far below the backstop — no truncation, got {:?}",
        out.diagnostics
    );
    let band_top = BASE_PRIMARY + SLOTS_PER_RULE - 1;
    assert!(
        out.filters.iter().all(|f| f.weight <= band_top),
        "every weight must stay inside the first rule's band"
    );
    // Sharing the band's top slot used to be how 300 targets fitted into
    // 256 of them. Packed, a rule cannot run out: the chunk count is bounded
    // by the slot partition, far below the band, so no two filters are
    // forced onto one weight any more.
    let at_top = out.filters.iter().filter(|f| f.weight == band_top).count();
    assert_eq!(
        at_top, 0,
        "packing leaves room in the band — nothing should be clamped to its top"
    );
}

/// The reason the rule band was packed at all: four 0xEF bugchecks were
/// traced to the BFE host degrading over hours under thousands of standing
/// filters, and after the kill switch was packed the rule band was the
/// largest producer left — about 2000 filters of 2260 on the first measured
/// run. This pins the shape of the fix, not a particular number.
#[test]
fn a_wide_rule_costs_filters_by_slot_not_by_address() {
    let cache = MockFqdnCacheLookup::new();
    let hosts = 300usize;
    for i in 0..hosts {
        cache.set_ips(
            &format!("h{i}.example.com"),
            vec![Ipv4Addr::new(10, (i / 256) as u8, (i % 256) as u8, 1)],
        );
    }
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    let covered: std::collections::HashSet<IpAddr> =
        out.filters.iter().flat_map(destination_ips).collect();
    assert_eq!(covered.len(), hosts, "every address stays covered");
    assert!(
        out.filters.len() <= nrr_platform_api::wfp_slotting::SLOT_COUNT as usize,
        "300 addresses must not cost 300 filters: got {}",
        out.filters.len()
    );

    // Recomputing the same rule book must produce the same filters, ids
    // included — a set that churns would reinstall the whole band on every
    // pass, which is the failure mode packing exists to avoid.
    let again = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let ids = |o: &CodegenOutput| -> Vec<u64> {
        let mut v: Vec<u64> = o.filters.iter().map(|f| f.id.raw).collect();
        v.sort_unstable();
        v
    };
    assert_eq!(ids(&out), ids(&again), "packing is content-addressed");
}

#[test]
fn suffix_domain_at_backstop_emits_truncated_diagnostic() {
    let cache = MockFqdnCacheLookup::new();
    for i in 0..SUFFIX_FANOUT_BACKSTOP {
        cache.set_ips(
            &format!("h{i}.example.com"),
            vec![Ipv4Addr::new(
                10,
                (i / 65536) as u8,
                (i / 256) as u8,
                (i % 256) as u8,
            )],
        );
    }
    let rule_book = book(vec![suffix_rule("r-suf", "example.com")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(
        out.diagnostics
            .contains(&CodegenDiagnostic::SuffixTruncated {
                rule_id: "r-suf".into(),
                suffix: "example.com".into(),
                cap: SUFFIX_FANOUT_BACKSTOP,
            }),
        "expected SuffixTruncated diagnostic when cached hosts >= backstop, got {:?}",
        out.diagnostics
    );
}

// ── Zone ────────────────────────────────────────────────────────────────

#[test]
fn zone_fans_out_over_cached_hosts_under_tld() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("ab.example", vec![Ipv4Addr::new(23, 10, 20, 136)]);
    cache.set_ips("cd.example", vec![Ipv4Addr::new(23, 10, 20, 137)]);
    let rule_book = book(vec![zone_rule("r-zone", "example")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(out.filters.len(), 2);
}

#[test]
fn zone_with_no_cached_hosts_emits_zone_empty_diagnostic() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![zone_rule("r-zone", "ru")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
    assert_eq!(
        out.diagnostics,
        vec![CodegenDiagnostic::ZoneEmpty {
            rule_id: "r-zone".into(),
            zone: "ru".into()
        }]
    );
}

// ── Application ─────────────────────────────────────────────────────────

#[test]
fn application_rule_emits_filter_with_app_pattern_and_no_remote_ip() {
    let cache = MockFqdnCacheLookup::new();
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
    let rule_book = book(vec![app_rule("r-app", "chrome.exe", false)], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // The name resolves to one concrete path → one app-id filter carrying the
    // RESOLVED PATH (not the raw name) so `FwpmGetAppIdFromFileName0` can key
    // on it at apply time.
    assert_eq!(out.filters.len(), 1);
    let f = &out.filters[0];
    assert!(f.remote_ip.is_none() && f.remote_ip_set.is_empty());
    assert_eq!(f.app_pattern.as_deref(), Some(r"C:\Apps\chrome.exe"));
    assert_eq!(f.action, WfpAction::Permit);
}

#[test]
fn app_observed_ips_are_marked_only_for_a_resolved_secondary_route_rule() {
    // The mark tells the orchestrator "the per-app pair covers this IP, no
    // per-destination pin needed" — so it may only appear when the pair
    // can actually arm (secondary role, route rule, exe resolved).
    let cache = MockFqdnCacheLookup::new();
    let observed = Ipv4Addr::new(203, 0, 113, 7);
    let app_obs = MockAppObservationLookup::new();
    app_obs.set_ips("chrome.exe", vec![observed]);
    let denylist = std::collections::HashSet::new();
    let run = |rule_book: &CanonicalRuleBook, resolver: &dyn AppPathResolver| {
        generate_filters(CodegenInput {
            sid: "S",
            rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &app_obs,
            app_resolver: resolver,
            secondary_ip_denylist: &denylist,
            zone_priority_over_ip: false,
            families: crate::enforcement_planner::FamilyScope::V4Only,
        })
    };
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);

    // Resolved secondary route rule → the observed IP is marked.
    let secondary = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
    assert_eq!(
        run(&secondary, &resolver).app_observed_secondary_ips,
        vec![observed]
    );
    // Unresolved exe → mirrors still emit, but no mark: no pair, no cover.
    assert!(run(&secondary, &NoopAppPathResolver)
        .app_observed_secondary_ips
        .is_empty());
    // Primary app rule → never marked (the per-dest kill-switch does not
    // protect primary destinations anyway).
    let primary = book(vec![app_rule("r-app", "chrome.exe", false)], vec![]);
    assert!(run(&primary, &resolver)
        .app_observed_secondary_ips
        .is_empty());
}

// ── Built-in VPN glob resolution ──────────────────────────────────────

#[test]
fn builtin_vpn_globs_resolve_to_concrete_paths_never_leaving_a_glob() {
    // A resolver that maps one built-in glob (`openvpn*`) to a real path and
    // knows nothing about the other built-ins.
    let cache = MockFqdnCacheLookup::new();
    let resolver = MockAppPathResolver::new()
        .with("openvpn.exe", vec![PathBuf::from(r"C:\Tools\openvpn.exe")]);
    // No app rules — we are exercising ONLY the built-in exempt resolution.
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // `openvpn*` matched the seeded `openvpn.exe` → its concrete path surfaces.
    assert_eq!(
        out.vpn_default_exempt_paths,
        vec![r"C:\Tools\openvpn.exe".to_string()],
        "a resolvable built-in glob yields its on-disk path",
    );
    // No glob character ever survives into the exempt path set — that is the
    // whole point (a glob stamped into ALE_APP_ID is silently dropped at apply).
    assert!(
        out.vpn_default_exempt_paths
            .iter()
            .all(|p| !p.contains('*') && !p.contains('?')),
        "no glob may leave the resolver",
    );
}

#[test]
fn builtin_vpn_globs_unresolved_yield_empty_exempt_set() {
    // NoopAppPathResolver resolves every built-in glob to nothing.
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(
        out.vpn_default_exempt_paths.is_empty(),
        "unresolvable built-in globs contribute nothing (they never enforced anyway)",
    );
}

#[test]
fn builtin_vpn_exempt_paths_are_deduped_and_sorted() {
    // `openvpn.exe` is matched by BOTH `*vpn*` and `openvpn*`, so its path is
    // resolved twice across the built-in globs — the union must dedup it. A
    // second client resolves to an alphabetically-earlier path to prove sorting.
    let cache = MockFqdnCacheLookup::new();
    let resolver = MockAppPathResolver::from_seed([
        (
            "openvpn.exe".to_string(),
            vec![PathBuf::from(r"C:\Z\vpn.exe")],
        ),
        (
            "wireguard.exe".to_string(),
            vec![PathBuf::from(r"C:\A\wg.exe")],
        ),
    ]);
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Deduped (openvpn.exe seen via two globs) and sorted ascending.
    assert_eq!(
        out.vpn_default_exempt_paths,
        vec![r"C:\A\wg.exe".to_string(), r"C:\Z\vpn.exe".to_string()],
    );
}

#[test]
fn app_rule_with_unresolved_exe_emits_diagnostic_and_no_app_id_filter() {
    let cache = MockFqdnCacheLookup::new();
    // The resolver knows nothing → the name resolves to zero paths.
    let resolver = MockAppPathResolver::new();
    // …but the app HAS observed destinations, so the /32 mirrors still emit.
    let app_obs = MockAppObservationLookup::new();
    app_obs.set_ips("chrome.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
    let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &app_obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // No ALE_APP_ID (app_pattern) filter — the WFP condition needs a real
    // path, which an unresolved name cannot supply.
    assert!(
        out.filters.iter().all(|f| f.app_pattern.is_none()),
        "an unresolved app emits no ALE_APP_ID filter"
    );
    // The observed /32 mirror is still emitted (independent of resolution).
    assert_eq!(
        out.filters
            .iter()
            .filter(|f| f.remote_ip.is_some() || !f.remote_ip_set.is_empty())
            .count(),
        1
    );
    // And the diagnostic explains why the app-id filter is missing.
    assert!(out.diagnostics.contains(&CodegenDiagnostic::AppUnresolved {
        rule_id: "r-app".into(),
        app: "chrome.exe".into(),
    }));
}

#[test]
fn glob_app_rule_fans_out_one_app_id_filter_per_resolved_path() {
    let cache = MockFqdnCacheLookup::new();
    // A glob unions two distinct installs.
    let resolver = MockAppPathResolver::from_seed([
        (
            "disko.exe".to_string(),
            vec![PathBuf::from(r"C:\Y\disko.exe")],
        ),
        (
            "diskosync.exe".to_string(),
            vec![PathBuf::from(r"C:\Y\diskosync.exe")],
        ),
    ]);
    let rule_book = book(vec![], vec![glob_app_rule("r-g", "disko*.exe")]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // One ALE_APP_ID filter per resolved path.
    let app_id_filters: Vec<_> = out
        .filters
        .iter()
        .filter(|f| f.app_pattern.is_some())
        .collect();
    assert_eq!(app_id_filters.len(), 2);
    let patterns: Vec<String> = app_id_filters
        .iter()
        .filter_map(|f| f.app_pattern.clone())
        .collect();
    assert!(patterns.contains(&r"C:\Y\disko.exe".to_string()));
    assert!(patterns.contains(&r"C:\Y\diskosync.exe".to_string()));
    // Distinct weights (no collision) and distinct ids per path.
    assert_ne!(app_id_filters[0].weight, app_id_filters[1].weight);
    assert_ne!(app_id_filters[0].id.raw, app_id_filters[1].id.raw);
}

#[test]
fn resolved_app_id_weight_sits_below_shifted_observation_mirrors() {
    let cache = MockFqdnCacheLookup::new();
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
    let app_obs = MockAppObservationLookup::new();
    app_obs.set_ips("chrome.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
    let rule_book = book(vec![app_rule("r-app", "chrome.exe", false)], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &app_obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let app_id = out
        .filters
        .iter()
        .find(|f| f.app_pattern.is_some())
        .expect("app-id filter");
    let mirror = out
        .filters
        .iter()
        .find(|f| f.remote_ip.is_some() || !f.remote_ip_set.is_empty())
        .expect("observation /32 mirror");
    // The app-id band (slots 0..APP_PATH_FANOUT_CAP) sits strictly below the
    // observation-mirror band (slots APP_PATH_FANOUT_CAP + 1 + i) — no
    // weight collision between the two fan-outs of the same rule.
    assert!(app_id.weight < mirror.weight);
    assert_eq!(mirror.weight - app_id.weight, APP_PATH_FANOUT_CAP + 1);
}

// ── Default behaviour modes ─────────────────────────────────────────────

#[test]
fn strict_secondary_fail_closed_emits_block_catch_all() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(out.filters.len(), 1);
    let f = &out.filters[0];
    assert_eq!(f.action, WfpAction::Block);
    assert!(f.remote_ip.is_none() && f.remote_ip_set.is_empty());
    assert_eq!(f.weight, DEFAULT_BLOCK_WEIGHT);
    assert_eq!(
        out.diagnostics,
        vec![CodegenDiagnostic::FailClosedDefaultEmitted]
    );
}

#[test]
fn prefer_primary_does_not_emit_default_block() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
}

#[test]
fn prefer_secondary_when_available_does_not_emit_default_block() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferSecondaryWhenAvailable,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
}

// ── Disabled rules ──────────────────────────────────────────────────────

#[test]
fn disabled_rule_is_skipped_with_diagnostic() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![disabled_rule("r-off", Ipv4Addr::new(1, 1, 1, 1))],
        vec![],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.filters.is_empty());
    assert_eq!(
        out.diagnostics,
        vec![CodegenDiagnostic::SkippedDisabled {
            rule_id: "r-off".into()
        }]
    );
}

// ── Determinism / weights ───────────────────────────────────────────────

#[test]
fn repeated_generation_produces_identical_filter_ids() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("a.test", vec![Ipv4Addr::new(1, 1, 1, 1)]);
    let rule_book = book(
        vec![
            exact_fqdn_rule("r-1", "a.test"),
            exact_ip_rule("r-2", Ipv4Addr::new(2, 2, 2, 2)),
        ],
        vec![app_rule("r-3", "chrome.exe", false)],
    );
    let ids = |out: &CodegenOutput| -> Vec<u64> { out.filters.iter().map(|f| f.id.raw).collect() };
    let a = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let b = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(ids(&a), ids(&b));
}

#[test]
fn a_rule_position_past_the_band_shares_the_last_slot_instead_of_leaving_the_band() {
    // Nothing upstream caps `pos`, and a band holds 4096 rules. Before the
    // clamp the 8192nd primary rule landed on the kill-switch permit band —
    // a user rule silently outranking the guard.
    let band_top = BASE_PRIMARY + BAND_WIDTH;
    assert!(rule_weight(BASE_PRIMARY, MAX_RULE_SLOT, SLOTS_PER_RULE - 1) < band_top);
    assert!(rule_weight(BASE_PRIMARY, u64::from(u32::MAX), 0) < band_top);
    assert_eq!(
        rule_weight(BASE_PRIMARY, MAX_RULE_SLOT + 5, 0),
        rule_weight(BASE_PRIMARY, MAX_RULE_SLOT, 0),
        "positions past the cap share the last slot deterministically"
    );
    // A fan-out index cannot climb into the next rule's slot either.
    assert_eq!(
        rule_weight(BASE_PRIMARY, 0, SLOTS_PER_RULE + 10),
        rule_weight(BASE_PRIMARY, 0, SLOTS_PER_RULE - 1)
    );
}

#[test]
fn primary_filters_outrank_secondary_filters_by_weight() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![exact_ip_rule("r-p", Ipv4Addr::new(1, 1, 1, 1))],
        vec![exact_ip_rule("r-s", Ipv4Addr::new(2, 2, 2, 2))],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let primary_weight = out
        .filters
        .iter()
        .find(|f| f.covers_v4(Ipv4Addr::new(1, 1, 1, 1)))
        .unwrap()
        .weight;
    let secondary_weight = out
        .filters
        .iter()
        .find(|f| f.covers_v4(Ipv4Addr::new(2, 2, 2, 2)))
        .unwrap()
        .weight;
    assert!(
        primary_weight > secondary_weight,
        "primary {primary_weight:#x} must outrank secondary {secondary_weight:#x}"
    );
}

#[test]
fn per_sid_user_sid_stamped_on_every_filter() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
        vec![exact_ip_rule("r-2", Ipv4Addr::new(2, 2, 2, 2))],
    );
    let out = generate_filters(CodegenInput {
        sid: "S-1-5-21-XYZ",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    for f in &out.filters {
        assert_eq!(f.user_sid.as_deref(), Some("S-1-5-21-XYZ"));
    }
}

#[test]
fn different_sids_produce_different_filter_ids() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
        vec![],
    );
    let a = generate_filters(CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let b = generate_filters(CodegenInput {
        sid: "S-1-5-21-B",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_ne!(a.filters[0].id.raw, b.filters[0].id.raw);
}

#[test]
fn primary_and_secondary_rule_with_same_id_produce_different_filter_ids() {
    let cache = MockFqdnCacheLookup::new();
    // Same id "r-1" in both lists is legal — they're separate
    // namespaces per role. Filter ids must still differ.
    let rule_book = book(
        vec![exact_ip_rule("r-1", Ipv4Addr::new(1, 1, 1, 1))],
        vec![exact_ip_rule("r-1", Ipv4Addr::new(2, 2, 2, 2))],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let ids: Vec<u64> = out.filters.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[test]
fn fanout_idx_keeps_filter_ids_unique_for_multi_ip_hostname() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(
        "x.test",
        vec![
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(1, 1, 1, 2),
            Ipv4Addr::new(1, 1, 1, 3),
        ],
    );
    let rule_book = book(vec![exact_fqdn_rule("r-1", "x.test")], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let ids: std::collections::HashSet<u64> = out.filters.iter().map(|f| f.id.raw).collect();
    assert_eq!(ids.len(), 3, "fan-out per IP must yield distinct ids");
}

#[test]
fn no_rule_no_strict_mode_yields_empty_output() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(vec![], vec![]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(out.is_empty());
    assert!(out.diagnostics.is_empty());
}

// ── secondary_dest_ips (block 16.18.vpn kill-switch) ────────────────────

#[test]
fn secondary_dest_ips_collects_only_secondary_rule_ips() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![exact_ip_rule("r-p", Ipv4Addr::new(10, 0, 0, 1))],
        vec![exact_ip_rule("r-s", Ipv4Addr::new(203, 0, 113, 9))],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(
        out.secondary_dest_ips,
        vec![Ipv4Addr::new(203, 0, 113, 9)],
        "only the secondary rule's IP is protected; the primary rule's is excluded"
    );
}

#[test]
fn secondary_dest_ips_dedupes_across_rules_and_fanout() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("a.test", vec![Ipv4Addr::new(5, 5, 5, 5)]);
    cache.set_ips("b.test", vec![Ipv4Addr::new(5, 5, 5, 5)]); // same IP
    let rule_book = book(
        vec![],
        vec![
            exact_fqdn_rule("r-1", "a.test"),
            exact_fqdn_rule("r-2", "b.test"),
            exact_ip_rule("r-3", Ipv4Addr::new(5, 5, 5, 5)), // same IP again
        ],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert_eq!(
        out.secondary_dest_ips,
        vec![Ipv4Addr::new(5, 5, 5, 5)],
        "the same resolved IP across three secondary rules collapses to one"
    );
}

/// The failure this prevents, seen on a live machine: an application on the
/// additional link had once connected to the address of a site the user had
/// explicitly routed over the MAIN link. The address entered the
/// kill-switch set, and the site went dead in every browser on the machine.
/// Two of the user's own rules pointed one address in opposite directions,
/// and the outcome was neither — it was a block.
#[test]
fn an_app_rule_does_not_take_over_an_address_a_main_route_rule_names() {
    let shared = Ipv4Addr::new(203, 0, 113, 68);
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("blog.example", vec![shared]);
    let observations = MockAppObservationLookup::new();
    observations.set_ips("helper.exe", vec![shared]);
    let resolver =
        MockAppPathResolver::new().with("helper.exe", vec![PathBuf::from(r"C:\Apps\helper.exe")]);

    let rule_book = book(
        vec![exact_fqdn_rule("r-main", "blog.example")],
        vec![app_rule("r-app", "helper.exe", false)],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    assert!(
            !out.secondary_dest_ips.contains(&IpAddr::V4(shared)),
            "the app rule took over an address the main-route rule names; the kill-switch              would then block it for every process",
        );
    assert!(
        out.primary_dest_ips.contains(&IpAddr::V4(shared)),
        "the main-route rule keeps the address it named",
    );
    assert!(
        out.diagnostics.iter().any(|d| matches!(
            d,
            CodegenDiagnostic::AppDestinationClaimedByPrimary { ip, .. } if *ip == shared
        )),
        "the conflict must be reported, not silently resolved",
    );
    // The per-process filter is untouched: the app is still routed over the
    // additional link for everything else it talks to.
    assert!(
        out.filters.iter().any(|f| f.app_pattern.is_some()),
        "the app rule itself still enforces",
    );
}

/// "Never observed" sends the user off to run the application. When every
/// address it WAS seen using went to a main-link rule, that advice is wrong
/// and the refusals above already carry the real reason.
#[test]
fn an_app_whose_every_address_was_claimed_is_not_reported_as_unobserved() {
    let shared = Ipv4Addr::new(203, 0, 113, 68);
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("blog.example", vec![shared]);
    let observations = MockAppObservationLookup::new();
    observations.set_ips("helper.exe", vec![shared]);
    let resolver =
        MockAppPathResolver::new().with("helper.exe", vec![PathBuf::from(r"C:\Apps\helper.exe")]);
    let rule_book = book(
        vec![exact_fqdn_rule("r-main", "blog.example")],
        vec![app_rule("r-app", "helper.exe", false)],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    assert!(
        out.diagnostics
            .iter()
            .any(|d| matches!(d, CodegenDiagnostic::AppDestinationClaimedByPrimary { .. })),
        "the real reason is reported",
    );
    assert!(
        !out.diagnostics
            .iter()
            .any(|d| matches!(d, CodegenDiagnostic::AppUnobserved { .. })),
        "and the misleading one is not: the process WAS seen",
    );
}

/// The mirror case: an address NO main-route rule names is taken over as
/// before. The guard must not turn into "app rules never route anything".
#[test]
fn an_app_rule_still_claims_addresses_nobody_else_named() {
    let only_app = Ipv4Addr::new(203, 0, 113, 9);
    let cache = MockFqdnCacheLookup::new();
    let observations = MockAppObservationLookup::new();
    observations.set_ips("helper.exe", vec![only_app]);
    let resolver =
        MockAppPathResolver::new().with("helper.exe", vec![PathBuf::from(r"C:\Apps\helper.exe")]);

    let rule_book = book(Vec::new(), vec![app_rule("r-app", "helper.exe", false)]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    assert!(out.secondary_dest_ips.contains(&IpAddr::V4(only_app)));
}

#[test]
fn secondary_dest_ips_skips_app_match_rules() {
    let cache = MockFqdnCacheLookup::new();
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
    let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // The resolved app-id filter carries an `app_pattern` but no `remote_ip`,
    // so it contributes nothing to the kill-switch's protected dest set.
    assert!(
        out.filters.iter().any(|f| f.app_pattern.is_some()),
        "the resolved app-id filter is emitted"
    );
    assert!(
        out.secondary_dest_ips.is_empty(),
        "an UNOBSERVED app rule has no IP destination to protect yet"
    );
}

#[test]
fn app_rule_routes_observed_ips_as_secondary_dest() {
    let cache = MockFqdnCacheLookup::new();
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
    let app_obs = MockAppObservationLookup::new();
    app_obs.set_ips(
        "chrome.exe",
        vec![Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)],
    );
    let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &app_obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // The app's observed IPs become secondary /32 destinations the
    // kill-switch protects — same as a domain rule's resolved IPs.
    assert_eq!(
        out.secondary_dest_ips,
        vec![Ipv4Addr::new(203, 0, 113, 7), Ipv4Addr::new(203, 0, 113, 8)]
    );
    // Two /32 Permits (one per observed IP), each carrying remote_ip,
    // plus the per-process Permit (no remote_ip).
    assert_eq!(
        out.filters
            .iter()
            .filter(|f| f.remote_ip.is_some() || !f.remote_ip_set.is_empty())
            .count(),
        2
    );
}

#[test]
fn secondary_app_patterns_collects_secondary_route_apps() {
    let cache = MockFqdnCacheLookup::new();
    let resolver =
        MockAppPathResolver::new().with("chrome.exe", vec![PathBuf::from(r"C:\Apps\chrome.exe")]);
    // An UNOBSERVED secondary app rule still emits the per-process app-id
    // Permit (for each resolved path), so its RESOLVED PATH is collected for
    // the per-app kill-switch regardless of whether any destination has been
    // observed yet.
    let rule_book = book(vec![], vec![app_rule("r-app", "chrome.exe", false)]);
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // The resolved path — not the raw name — is what the per-app kill-switch
    // pins, so `secondary_app_patterns` now carries it.
    assert_eq!(
        out.secondary_app_patterns,
        vec![r"C:\Apps\chrome.exe".to_string()]
    );
}

#[test]
fn secondary_app_patterns_excludes_primary_and_block_apps() {
    let cache = MockFqdnCacheLookup::new();
    let resolver = MockAppPathResolver::from_seed([
        (
            "primary.exe".to_string(),
            vec![PathBuf::from(r"C:\Apps\primary.exe")],
        ),
        (
            "secondary.exe".to_string(),
            vec![PathBuf::from(r"C:\Apps\secondary.exe")],
        ),
        (
            "evil.exe".to_string(),
            vec![PathBuf::from(r"C:\Apps\evil.exe")],
        ),
    ]);
    let mut blocked_app = app_rule("r-block-app", "evil.exe", false);
    blocked_app.action = nrr_domain::RuleAction::Block;
    let rule_book = book(
        vec![app_rule("r-prim", "primary.exe", false)],
        vec![app_rule("r-sec", "secondary.exe", false), blocked_app],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &resolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Only the secondary ROUTE app is protected: the primary app uses the
    // primary NIC (never killed), and the block app is being dropped, not
    // routed via the secondary adapter. The pattern carried is the RESOLVED PATH.
    assert_eq!(
        out.secondary_app_patterns,
        vec![r"C:\Apps\secondary.exe".to_string()]
    );
}

// ── Block action ─────────────────────────────────────────────────────────

fn block_exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
    let mut r = exact_ip_rule(id, addr);
    r.action = nrr_domain::RuleAction::Block;
    r
}

#[test]
fn block_rule_emits_ale_and_packet_block_at_block_band() {
    let cache = MockFqdnCacheLookup::new();
    let addr = Ipv4Addr::new(203, 0, 113, 5);
    // Block rule lives in the secondary set — membership is irrelevant.
    let rule_book = book(vec![], vec![block_exact_ip_rule("r-1", addr)]);
    let out = generate_filters(CodegenInput {
        sid: "S-1-5-21-A",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Exactly two filters: an ALE-layer block and a packet-layer mirror.
    assert_eq!(out.filters.len(), 2);
    assert!(out.filters.iter().all(|f| f.action == WfpAction::Block));
    assert!(out.filters.iter().all(|f| f.covers_v4(addr)));
    let ale = out
        .filters
        .iter()
        .find(|f| f.layer == WfpLayerKey::AleAuthConnectV4)
        .expect("ALE block");
    let pkt = out
        .filters
        .iter()
        .find(|f| f.layer == WfpLayerKey::OutboundIpPacketV4)
        .expect("packet-layer block (ICMP parity)");
    // Block band beats the kill-switch permit band (0x0040_0000).
    assert!(
        ale.weight >= BASE_BLOCK,
        "block must use the BASE_BLOCK band"
    );
    // ALE block is SID-scoped; packet layer has no ALE_USER_ID → system-wide.
    assert_eq!(ale.user_sid.as_deref(), Some("S-1-5-21-A"));
    assert!(pkt.user_sid.is_none());
    assert_ne!(
        ale.id, pkt.id,
        "block filter ids must be distinct per layer"
    );
}

#[test]
fn block_rule_ip_is_excluded_from_secondary_dest_ips() {
    let cache = MockFqdnCacheLookup::new();
    let routed = Ipv4Addr::new(203, 0, 113, 9);
    let blocked = Ipv4Addr::new(203, 0, 113, 5);
    let rule_book = book(
        vec![],
        vec![
            exact_ip_rule("r-route", routed),
            block_exact_ip_rule("r-block", blocked),
        ],
    );
    let out = generate_filters(CodegenInput {
        sid: "S",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &NoopAppPathResolver,
        secondary_ip_denylist: &std::collections::HashSet::new(),
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    // Only the routed (Permit) destination is protected by the kill-switch;
    // a dropped destination must never be handed to it.
    assert_eq!(out.secondary_dest_ips, vec![routed]);
    assert!(!out.secondary_dest_ips.contains(&IpAddr::V4(blocked)));
}

#[test]
fn block_filter_ids_are_deterministic_across_reapply() {
    let cache = MockFqdnCacheLookup::new();
    let rule_book = book(
        vec![],
        vec![block_exact_ip_rule("r-1", Ipv4Addr::new(203, 0, 113, 5))],
    );
    let mk = || {
        generate_filters(CodegenInput {
            sid: "S",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &MockAppObservationLookup::new(),
            app_resolver: &NoopAppPathResolver,
            secondary_ip_denylist: &std::collections::HashSet::new(),
            zone_priority_over_ip: false,
            families: crate::enforcement_planner::FamilyScope::V4Only,
        })
    };
    let a = mk();
    let b = mk();
    assert_eq!(a.filters, b.filters);
}

/// The setting reaches ENFORCEMENT, not just explain.
///
/// A zone on the main link and an exact-address rule on the additional one
/// name the same address. The rule model's default is that the exact
/// address wins; the filter codegen used to hand it to the main link no
/// matter what the user had chosen, because a literal address went into its
/// side of the arbiter unconditionally.
#[test]
fn the_zone_priority_setting_changes_which_link_the_filters_pin() {
    use crate::address_ownership::{AddressOwnership, Link, ZoneVsIpOrder};

    let ip = std::net::Ipv4Addr::new(203, 0, 113, 7);
    let cache = crate::fqdn_cache_lookup::MockFqdnCacheLookup::new();
    cache.set_ips("shop.example.com", vec![ip]);

    let book = book(vec![zone_rule("p1", "com")], vec![exact_ip_rule("s1", ip)]);

    let default_order = AddressOwnership::resolve_with_order(
        &book,
        &cache,
        ZoneVsIpOrder::from_zone_priority_over_ip(false),
    );
    assert_eq!(
        default_order.owner_of(IpAddr::V4(ip)),
        Some(Link::Additional)
    );

    let zone_first = AddressOwnership::resolve_with_order(
        &book,
        &cache,
        ZoneVsIpOrder::from_zone_priority_over_ip(true),
    );
    assert_eq!(zone_first.owner_of(IpAddr::V4(ip)), Some(Link::Main));
}
