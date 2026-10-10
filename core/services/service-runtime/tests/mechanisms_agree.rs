//! The two mechanisms must agree about who owns an address.
//!
//! Routing and filtering are separate code paths that read the same rule book:
//! one decides where a packet leaves, the other decides whether it may leave at
//! all. When they disagree, the result is not "one of the two behaviours" — it
//! is a destination that is routed one way and dropped on the other, dead for
//! every process on the machine.
//!
//! That is not hypothetical. A live machine lost an ordinary direct host for
//! hours: an
//! application rule on the additional link had once been observed connecting to
//! its address, so the filter side pinned and then blocked it, while the route
//! side — which already had the guard — left it on the main link. The site was
//! named by the user's own main-link rule the whole time.
//!
//! These tests state the invariant rather than the incident: whatever the rule
//! book says, an address the main link claims never appears among the
//! destinations the filter side hands the kill-switch. Written as a sweep over
//! rule-book shapes, so the next way to reach the same contradiction fails here
//! instead of on someone's machine.

#![allow(clippy::expect_used)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use nrr_domain::canonical::{
    CanonicalAddressMatch, CanonicalAppMatch, CanonicalAppPattern, CanonicalRule,
    CanonicalRuleBook, CanonicalRuleSet,
};
use nrr_domain::{RouteBehaviorMode, RuleAction, RuleId};
use nrr_platform_api::MockAppPathResolver;
use nrr_service_runtime::app_observation_lookup::MockAppObservationLookup;
use nrr_service_runtime::enforcement_planner::{
    plan_route_rules, plan_route_rules_with_shapes, PlannerInput,
};
use nrr_service_runtime::fqdn_cache_lookup::MockFqdnCacheLookup;
use nrr_service_runtime::route_codegen::{address_rule_ips, generate_routes, SecondaryRouteTarget};
use nrr_service_runtime::wfp_codegen::{
    generate_filters, generate_filters_with_shapes, CodegenInput,
};

/// The address two rules end up fighting over.
const CONTESTED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 68);
/// An address only the application ever touches.
const APP_ONLY: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const HOST: &str = "blog.example";
const APP: &str = "helper.exe";

fn address_rule(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

fn app_rule(id: &str, process: &str) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: None,
        app_match: Some(CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact(process.into()),
            include_child_processes: false,
        }),
        comment: String::new(),
        action: RuleAction::Route,
        origin: None,
    }
}

/// Every way a main-link rule can name the contested address.
fn main_link_claims() -> Vec<(&'static str, CanonicalRule)> {
    vec![
        (
            "by literal address",
            address_rule(
                "r-ip",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(CONTESTED)),
            ),
        ),
        (
            "by exact name",
            address_rule("r-fqdn", CanonicalAddressMatch::ExactFqdn(HOST.into())),
        ),
        (
            "by domain suffix",
            address_rule("r-suffix", CanonicalAddressMatch::SuffixDomain(HOST.into())),
        ),
    ]
}

fn cache() -> MockFqdnCacheLookup {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(HOST, vec![CONTESTED]);
    cache
}

fn observations() -> MockAppObservationLookup {
    let obs = MockAppObservationLookup::new();
    obs.set_ips(APP, vec![CONTESTED, APP_ONLY]);
    obs
}

fn resolver() -> MockAppPathResolver {
    MockAppPathResolver::new().with(APP, vec![PathBuf::from(r"C:\Apps\helper.exe")])
}

fn target() -> SecondaryRouteTarget {
    SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 88, 0, 1),
        gateway_v6: None,
        interface_index: 42,
    }
}

/// The invariant, over every shape of main-link claim: an address the main link
/// names is never handed to the kill-switch as a protected secondary
/// destination, and never routed to the additional link either.
#[test]
fn an_address_the_main_link_names_is_never_taken_over_by_an_app_rule() {
    for (how, main_rule) in main_link_claims() {
        let cache = cache();
        let observations = observations();
        let resolver = resolver();
        let rule_book = CanonicalRuleBook {
            primary: CanonicalRuleSet::from_rules(vec![main_rule]),
            secondary: CanonicalRuleSet::from_rules(vec![app_rule("r-app", APP)]),
        };

        let filters = generate_filters(CodegenInput {
            sid: "S-1-5-21-TEST",
            rule_book: &rule_book,
            behavior_mode: RouteBehaviorMode::PreferPrimary,
            fqdn_cache: &cache,
            app_observations: &observations,
            app_resolver: &resolver,
            secondary_ip_denylist: &HashSet::new(),
            zone_priority_over_ip: false,
            families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
            packet_blocks: true,
        });
        let routes = generate_routes(
            RouteBehaviorMode::PreferPrimary,
            &rule_book,
            None,
            &target(),
            &cache,
            &observations,
            &HashSet::new(),
            nrr_service_runtime::address_ownership::ZoneVsIpOrder::default(),
            &[],
        );

        assert!(
            !filters.secondary_dest_ips.contains(&IpAddr::V4(CONTESTED)),
            "{how}: the filter side took over an address the main link names — the kill-switch \
             would block it for every process",
        );
        assert!(
            !routes.routes.iter().any(|r| r.destination == CONTESTED),
            "{how}: the route side steered an address the main link names onto the other link",
        );
        // The app rule is not disarmed by the guard: what nobody else named is
        // still its own.
        assert!(
            filters.secondary_dest_ips.contains(&IpAddr::V4(APP_ONLY)),
            "{how}: the guard swallowed a destination no other rule claims",
        );
    }
}

/// The two sides must agree on the whole set, not merely on the contested
/// address: any destination the filter side protects on the additional link is
/// one the route side actually steers there. A protected address with no route
/// is a block with nowhere to go.
#[test]
fn every_protected_destination_is_one_the_routes_actually_steer() {
    let cache = cache();
    let observations = observations();
    let resolver = resolver();
    let rule_book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![address_rule(
            "r-main",
            CanonicalAddressMatch::ExactFqdn(HOST.into()),
        )]),
        secondary: CanonicalRuleSet::from_rules(vec![
            app_rule("r-app", APP),
            address_rule(
                "r-sec",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4))),
            ),
        ]),
    };

    let filters = generate_filters(CodegenInput {
        sid: "S-1-5-21-TEST",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &HashSet::new(),
        zone_priority_over_ip: false,
        families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
        packet_blocks: true,
    });
    let routes = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &rule_book,
        None,
        &target(),
        &cache,
        &observations,
        &HashSet::new(),
        nrr_service_runtime::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );

    let steered: HashSet<Ipv4Addr> = routes
        .routes
        .iter()
        .filter_map(|r| match r.destination {
            IpAddr::V4(d) => Some(d),
            IpAddr::V6(_) => None,
        })
        .collect();
    let orphaned: Vec<Ipv4Addr> = filters
        .secondary_dest_ips
        .iter()
        .filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            // The Windows route producer is v4-only, so a v6 destination has
            // no route to be orphaned from — see the seam in `route_codegen`.
            IpAddr::V6(_) => None,
        })
        .filter(|ip| !steered.contains(ip))
        .collect();

    assert!(
        orphaned.is_empty(),
        "protected on the additional link but not routed there: {orphaned:?} — traffic to these \
         is blocked when the link drops and has no path to it when the link is up",
    );
}

/// The definition itself: what the main link claims is read the same way on both
/// sides. Two definitions of "claimed" is how the halves drift apart again.
#[test]
fn both_sides_read_the_main_links_claim_from_one_definition() {
    let cache = cache();
    let rules = CanonicalRuleSet::from_rules(vec![address_rule(
        "r-main",
        CanonicalAddressMatch::ExactFqdn(HOST.into()),
    )]);

    let claimed = address_rule_ips(&rules, &cache);

    assert!(claimed.contains(&CONTESTED));
    assert!(!claimed.contains(&APP_ONLY));
}

/// The mirror of the incident, and the rule stated plainly: an address rule
/// wins over an application rule REGARDLESS of which link each is on.
///
/// Here the tunnel's own zone rule names the address and the application rule
/// sits on the main link. If the program's observation won, a host the user
/// deliberately routes through the tunnel would leave over the open link
/// whenever that particular program touched it — the leak version of the same
/// mistake that produced the dead site.
#[test]
fn an_address_rule_wins_over_an_app_rule_on_either_link() {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips("api.example.com", vec![CONTESTED]);
    let observations = MockAppObservationLookup::new();
    observations.set_ips(APP, vec![CONTESTED, APP_ONLY]);
    let resolver = resolver();

    // Zone rule on the ADDITIONAL link; application rule on the MAIN link.
    let rule_book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![app_rule("r-app", APP)]),
        secondary: CanonicalRuleSet::from_rules(vec![address_rule(
            "r-zone",
            CanonicalAddressMatch::SuffixDomain("example.com".into()),
        )]),
    };

    let filters = generate_filters(CodegenInput {
        sid: "S-1-5-21-TEST",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &HashSet::new(),
        zone_priority_over_ip: false,
        families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
        packet_blocks: true,
    });

    assert!(
        filters.secondary_dest_ips.contains(&IpAddr::V4(CONTESTED)),
        "the address rule that names it must keep the address on its own link",
    );
    assert!(
        !filters.primary_dest_ips.contains(&IpAddr::V4(CONTESTED)),
        "the app rule on the main link took an address the tunnel's own rule names — that host would leave over the open link whenever this program touched it",
    );
    // And what only the program knows about is still the program's.
    assert!(filters.primary_dest_ips.contains(&IpAddr::V4(APP_ONLY)));
}

/// The census is the second half of the same question, and it went missing on
/// the filter side: an address somebody the rule set never named is ALSO using
/// must not be pinned — a `/32` filter is no more process-scoped than a route,
/// so the kill-switch would block that process's traffic too.
#[test]
fn a_destination_another_process_uses_is_pinned_by_neither_mechanism() {
    let cache = cache();
    let observations = observations();
    observations.set_used_outside(APP_ONLY);
    let resolver = resolver();
    let rule_book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(Vec::new()),
        secondary: CanonicalRuleSet::from_rules(vec![app_rule("r-app", APP)]),
    };

    let filters = generate_filters(CodegenInput {
        sid: "S-1-5-21-TEST",
        rule_book: &rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &observations,
        app_resolver: &resolver,
        secondary_ip_denylist: &HashSet::new(),
        zone_priority_over_ip: false,
        families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
        packet_blocks: true,
    });
    let routes = generate_routes(
        RouteBehaviorMode::PreferPrimary,
        &rule_book,
        None,
        &target(),
        &cache,
        &observations,
        &HashSet::new(),
        nrr_service_runtime::address_ownership::ZoneVsIpOrder::default(),
        &[],
    );

    assert!(
        !filters.secondary_dest_ips.contains(&IpAddr::V4(APP_ONLY)),
        "the filter side pinned a destination another process is using; the kill-switch would cut that process off too",
    );
    assert!(
        !routes.routes.iter().any(|r| r.destination == APP_ONLY),
        "the route side steered a destination another process is using",
    );
    // Untouched by the census, so still the app rule's own.
    assert!(
        filters.secondary_dest_ips.contains(&IpAddr::V4(CONTESTED)),
        "the census swallowed a destination nobody else uses",
    );
}

/// The neutral planner is the enforcement path on Linux and the shadow
/// comparison on Windows. It read the observations raw, so it reproduced the
/// incident on one OS and reported permanent false drift on the other.
#[test]
fn the_neutral_planner_reads_the_same_arbiter() {
    let cache = cache();
    let observations = observations();
    observations.set_used_outside(APP_ONLY);
    let resolver = resolver();
    let rule_book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![address_rule(
            "r-main",
            CanonicalAddressMatch::ExactFqdn(HOST.into()),
        )]),
        secondary: CanonicalRuleSet::from_rules(vec![app_rule("r-app", APP)]),
    };

    let flows = plan_route_rules(
        &rule_book,
        "S-1-5-21-TEST",
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            ipv6: nrr_service_runtime::enforcement_planner::Ipv6Guard::Off,
            fqdn_cache: &cache,
            app_resolver: &resolver,
            app_observations: &observations,
            zone_priority_over_ip: false,
            secondary_ip_denylist: &std::collections::HashSet::new(),
            packet_blocks: true,
        },
    )
    .0;

    let secondary_hosts: Vec<Ipv4Addr> = flows
        .iter()
        .filter(|f| {
            f.precedence.class
                == nrr_platform_api::enforcement::PrecedenceClass::RouteRule(
                    nrr_shared::RouteRole::Secondary,
                )
        })
        .filter_map(|f| match f.flow.dst {
            nrr_platform_api::enforcement::DstMatch::HostV4(ip) => Some(ip),
            _ => None,
        })
        .collect();

    assert!(
        !secondary_hosts.contains(&CONTESTED),
        "the planner pinned an address the main link names: {secondary_hosts:?}",
    );
    assert!(
        !secondary_hosts.contains(&APP_ONLY),
        "the planner pinned an address another process is using: {secondary_hosts:?}",
    );
}

/// The gate that keeps the others honest: production code reaches the
/// observation store through the arbiter, never directly. A new mechanism that
/// queries `ips_for_app` itself is a new place to forget one of the two checks
/// — which is exactly how the filter side lost the census.
#[test]
fn only_the_arbiter_reads_the_observation_store() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let (mut scanned, mut stripped) = (0usize, 0usize);
    let mut stripped_files = 0usize;
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("src is readable") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let file = path.file_name().unwrap_or_default().to_string_lossy();
            // A module's unit tests now live in `<module>/tests.rs` rather than
            // in a `#[cfg(test)] mod tests` block, so the strip below never
            // fires for them and every fixture would read as production. The
            // file IS the test module; skip it the same way.
            if file == "tests.rs" {
                stripped += 1;
                stripped_files += 1;
                continue;
            }
            // The arbiter itself, and the store that defines the query. Plus
            // the cross-session memory, which persists observations for a warm
            // start and emits no filter, route or block of its own — what it
            // re-seeds is read back through the gate like any other
            // observation. It holds no address cache, so it could not resolve
            // ownership even if it wanted to.
            if matches!(
                file.as_ref(),
                "address_ownership.rs" | "app_observation_lookup.rs" | "app_destination_memory.rs"
            ) {
                continue;
            }
            let body = std::fs::read_to_string(&path).expect("readable source");
            scanned += 1;
            // Test modules declare their own fixtures against the raw store, so
            // stop at the first one. Walking lines rather than splitting on a
            // literal keeps the strip honest on a CRLF checkout, where the
            // literal never matches and the whole file reads as production.
            for (n, line) in body.lines().enumerate() {
                let head = line.trim_start();
                if head.starts_with("#[cfg(test)]") || head.starts_with("#[cfg(all(test") {
                    stripped += 1;
                    break;
                }
                if line.contains(".ips_for_app(") || line.contains(".destination_used_outside(") {
                    offenders.push(format!("{}:{}", file, n + 1));
                }
            }
        }
    }
    // Positive control: a guard that reads nothing, or that never recognises a
    // test module, passes for the wrong reason.
    assert!(scanned > 0, "the guard read no sources — it is blind");
    assert!(
        stripped > 0,
        "no test module was recognised in {scanned} files: the strip is broken, so every fixture would count as production",
    );
    assert!(
        stripped_files > 0,
        "no `<module>/tests.rs` and no `<module>/tests/` file was recognised: \n         unit tests moved into their own files, and a strip that only knows \n         `#[cfg(test)]` blocks would read every one of them as production",
    );
    assert!(
        offenders.is_empty(),
        "these read the observation store without going through AppDestinationGate, so nothing forces them to apply both ownership and the census: {offenders:?}",
    );
}

// ── Block rules in the specificity contest ─────────────────────────────────
//
// The narrower rule wins whatever its action, and the engine's `match_sample`
// is the reference answer. A Block used to sit in a weight band above every
// route with nothing arbitrating it, so a zone Block dropped a host an exact
// route named.

const NARROW_HOST: &str = "a.example";
const NARROW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const ZONE_ONLY_HOST: &str = "b.example";
const ZONE_ONLY_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 20);

type Spec = nrr_platform_api::types::WfpFilterSpec;
use nrr_platform_api::types::WfpAction;

fn block_rule(id: &str, m: CanonicalAddressMatch) -> CanonicalRule {
    CanonicalRule {
        action: RuleAction::Block,
        ..address_rule(id, m)
    }
}

fn zone_cache() -> MockFqdnCacheLookup {
    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(NARROW_HOST, vec![NARROW_IP]);
    cache.set_ips(ZONE_ONLY_HOST, vec![ZONE_ONLY_IP]);
    cache
}

fn codegen(rule_book: &CanonicalRuleBook, cache: &MockFqdnCacheLookup) -> Vec<Spec> {
    generate_filters(CodegenInput {
        sid: "S-1-5-21-TEST",
        rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &MockAppPathResolver::new(),
        secondary_ip_denylist: &HashSet::new(),
        zone_priority_over_ip: false,
        families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
        packet_blocks: true,
    })
    .filters
}

fn covering(filters: &[Spec], action: WfpAction, ip: Ipv4Addr) -> impl Iterator<Item = &Spec> {
    filters
        .iter()
        .filter(move |f| f.action == action && f.covers_v4(ip))
}

fn blocked_by_planner(
    rule_book: &CanonicalRuleBook,
    cache: &MockFqdnCacheLookup,
    ip: Ipv4Addr,
) -> bool {
    plan_route_rules(
        rule_book,
        "S-1-5-21-TEST",
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            ipv6: nrr_service_runtime::enforcement_planner::Ipv6Guard::Off,
            fqdn_cache: cache,
            app_resolver: &MockAppPathResolver::new(),
            app_observations: &MockAppObservationLookup::new(),
            zone_priority_over_ip: false,
            secondary_ip_denylist: &HashSet::new(),
            packet_blocks: true,
        },
    )
    .0
    .iter()
    .any(|f| {
        f.verdict == nrr_platform_api::enforcement::Verdict::Block
            && f.flow.dst == nrr_platform_api::enforcement::DstMatch::HostV4(ip)
    })
}

/// The reference engine's verdict for a connection to `host` at `ip`.
fn engine_blocks(rule_book: &CanonicalRuleBook, host: &str, ip: Ipv4Addr) -> bool {
    use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
    match nrr_domain::decision_engine_input::match_sample(
        rule_book,
        Some(host),
        Some(IpAddr::V4(ip)),
        None,
        ZonePriorityPolicy::default(),
        RouteBehaviorMode::PreferPrimary,
    ) {
        RequestedRouteDecision::MatchedRoute { candidate } => candidate.action == RuleAction::Block,
        RequestedRouteDecision::DefaultRoute { .. } => false,
    }
}

/// Every narrower way to route a host a zone Block covers.
fn narrow_routes() -> Vec<(&'static str, CanonicalRule)> {
    vec![
        (
            "exact name",
            address_rule(
                "r-exact",
                CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
            ),
        ),
        (
            "domain suffix",
            address_rule(
                "r-suffix",
                CanonicalAddressMatch::SuffixDomain(NARROW_HOST.into()),
            ),
        ),
        (
            "literal address",
            address_rule(
                "r-ip",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(NARROW_IP)),
            ),
        ),
    ]
}

#[test]
fn a_wide_block_does_not_drop_a_host_a_narrower_route_names() {
    for (how, narrow) in narrow_routes() {
        for block_on_main in [true, false] {
            let wide = block_rule("b-zone", CanonicalAddressMatch::Zone("example".into()));
            let (primary, secondary) = if block_on_main {
                (vec![wide], vec![narrow.clone()])
            } else {
                (vec![narrow.clone()], vec![wide])
            };
            let rule_book = CanonicalRuleBook {
                primary: CanonicalRuleSet::from_rules(primary),
                secondary: CanonicalRuleSet::from_rules(secondary),
            };
            let cache = zone_cache();
            let filters = codegen(&rule_book, &cache);

            assert!(
                !engine_blocks(&rule_book, NARROW_HOST, NARROW_IP),
                "{how}: the reference engine must route the narrower host",
            );
            assert!(
                covering(&filters, WfpAction::Block, NARROW_IP)
                    .next()
                    .is_none(),
                "{how}: the zone Block dropped a host the narrower route names",
            );
            assert!(
                covering(&filters, WfpAction::Permit, NARROW_IP)
                    .next()
                    .is_some(),
                "{how}: the narrower route lost its permit",
            );
            assert!(
                !blocked_by_planner(&rule_book, &cache, NARROW_IP),
                "{how}: the neutral planner still blocks the narrower host",
            );
            // Positive control: what only the zone names stays blocked on
            // every side.
            assert!(engine_blocks(&rule_book, ZONE_ONLY_HOST, ZONE_ONLY_IP));
            assert!(
                covering(&filters, WfpAction::Block, ZONE_ONLY_IP)
                    .next()
                    .is_some(),
                "{how}: the zone Block stopped blocking what nobody else names",
            );
            assert!(blocked_by_planner(&rule_book, &cache, ZONE_ONLY_IP));
        }
    }
}

#[test]
fn a_narrow_block_still_drops_a_host_a_wider_route_carries() {
    let rule_book = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![block_rule(
            "b-exact",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        )]),
        secondary: CanonicalRuleSet::from_rules(vec![address_rule(
            "r-zone",
            CanonicalAddressMatch::Zone("example".into()),
        )]),
    };
    let cache = zone_cache();
    let filters = codegen(&rule_book, &cache);

    assert!(engine_blocks(&rule_book, NARROW_HOST, NARROW_IP));
    // The zone's permit may cover the address too; the block has to be the
    // filter that fires, so it must outweigh every permit on it.
    let block = covering(&filters, WfpAction::Block, NARROW_IP)
        .map(|f| f.weight)
        .min()
        .expect("the narrower block must cover its host");
    if let Some(permit) = covering(&filters, WfpAction::Permit, NARROW_IP)
        .map(|f| f.weight)
        .max()
    {
        assert!(block > permit, "a permit outranks the narrower block");
    }
    assert!(blocked_by_planner(&rule_book, &cache, NARROW_IP));
    // Positive control: the rest of the zone is routed, not blocked.
    assert!(!engine_blocks(&rule_book, ZONE_ONLY_HOST, ZONE_ONLY_IP));
    assert!(covering(&filters, WfpAction::Block, ZONE_ONLY_IP)
        .next()
        .is_none());
    assert!(covering(&filters, WfpAction::Permit, ZONE_ONLY_IP)
        .next()
        .is_some());
    assert!(!blocked_by_planner(&rule_book, &cache, ZONE_ONLY_IP));
}

fn codegen_output(
    rule_book: &CanonicalRuleBook,
    cache: &MockFqdnCacheLookup,
) -> nrr_service_runtime::wfp_codegen::CodegenOutput {
    generate_filters(CodegenInput {
        sid: "S-1-5-21-TEST",
        rule_book,
        behavior_mode: RouteBehaviorMode::PreferPrimary,
        fqdn_cache: cache,
        app_observations: &MockAppObservationLookup::new(),
        app_resolver: &MockAppPathResolver::new(),
        secondary_ip_denylist: &HashSet::new(),
        zone_priority_over_ip: false,
        families: nrr_service_runtime::enforcement_planner::FamilyScope::V4Only,
        packet_blocks: true,
    })
}

/// The Block must be the filter that fires on `ip`: it outweighs every permit.
fn block_fires(filters: &[Spec], ip: Ipv4Addr) -> bool {
    let Some(block) = covering(filters, WfpAction::Block, ip)
        .map(|f| f.weight)
        .min()
    else {
        return false;
    };
    covering(filters, WfpAction::Permit, ip).all(|permit| block > permit.weight)
}

fn book_with(block: CanonicalRule, route: CanonicalRule, block_on_main: bool) -> CanonicalRuleBook {
    let (primary, secondary) = if block_on_main {
        (vec![block], vec![route])
    } else {
        (vec![route], vec![block])
    };
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

/// A literal-IP Block is an absolute veto: every mechanism drops the address
/// although a narrower name rule routes a host on it, and the route rule is
/// told so.
#[test]
fn a_literal_ip_block_vetoes_a_narrower_route_everywhere() {
    use nrr_service_runtime::app_enforcement_status::rule_conflicts_from;
    use nrr_shared::ipc_payloads::RuleConflictKind;

    for (how, narrow) in [
        (
            "exact name",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        ),
        (
            "domain suffix",
            CanonicalAddressMatch::SuffixDomain(NARROW_HOST.into()),
        ),
    ] {
        for block_on_main in [true, false] {
            let rule_book = book_with(
                block_rule(
                    "b-ip",
                    CanonicalAddressMatch::ExactIp(IpAddr::V4(NARROW_IP)),
                ),
                address_rule("r-narrow", narrow.clone()),
                block_on_main,
            );
            let cache = zone_cache();
            let out = codegen_output(&rule_book, &cache);

            assert!(
                engine_blocks(&rule_book, NARROW_HOST, NARROW_IP),
                "{how}: the engine must honour the veto",
            );
            assert!(
                block_fires(&out.filters, NARROW_IP),
                "{how}: codegen lost the veto"
            );
            assert!(
                blocked_by_planner(&rule_book, &cache, NARROW_IP),
                "{how}: the planner lost the veto",
            );

            let conflicts = rule_conflicts_from(&out.diagnostics, &rule_book);
            assert_eq!(conflicts.len(), 1, "{how}: {conflicts:?}");
            let c = &conflicts[0];
            assert_eq!(c.kind, RuleConflictKind::LiteralBlockOverridesRoute);
            assert_eq!(c.rule_id, "r-narrow");
            assert_eq!(c.other_rule_id, "b-ip");
            assert_eq!(c.ip, NARROW_IP.to_string());
            assert_eq!(c.host, NARROW_HOST);
        }
    }
}

/// Equal specificity across the two sets: the Block wins on every side,
/// wherever each rule sits.
#[test]
fn a_block_wins_a_tie_with_a_route_everywhere() {
    for (how, m) in [
        (
            "exact name",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        ),
        (
            "domain suffix",
            CanonicalAddressMatch::SuffixDomain(NARROW_HOST.into()),
        ),
        ("zone", CanonicalAddressMatch::Zone("example".into())),
    ] {
        for block_on_main in [true, false] {
            let rule_book = book_with(
                block_rule("b-1", m.clone()),
                address_rule("r-1", m.clone()),
                block_on_main,
            );
            let cache = zone_cache();
            let filters = codegen(&rule_book, &cache);

            assert!(
                engine_blocks(&rule_book, NARROW_HOST, NARROW_IP),
                "{how}, block on main {block_on_main}: the engine let the route win the tie",
            );
            assert!(
                block_fires(&filters, NARROW_IP),
                "{how}, block on main {block_on_main}: codegen let the route win the tie",
            );
            assert!(
                blocked_by_planner(&rule_book, &cache, NARROW_IP),
                "{how}, block on main {block_on_main}: the planner let the route win the tie",
            );
        }
    }
}

/// The accepted leak, made visible: a zone Block yields an address shared by a
/// narrowly routed host, so the zone's other host on it stays reachable — and
/// codegen reports exactly that host and the one that kept it open.
#[test]
fn a_block_that_yields_a_shared_address_reports_the_leak() {
    use nrr_service_runtime::app_enforcement_status::rule_conflicts_from;
    use nrr_shared::ipc_payloads::RuleConflictKind;

    let cache = MockFqdnCacheLookup::new();
    cache.set_ips(NARROW_HOST, vec![NARROW_IP]);
    cache.set_ips(ZONE_ONLY_HOST, vec![NARROW_IP, ZONE_ONLY_IP]);
    let rule_book = book_with(
        block_rule("b-zone", CanonicalAddressMatch::Zone("example".into())),
        address_rule(
            "r-exact",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        ),
        false,
    );
    let out = codegen_output(&rule_book, &cache);

    assert!(covering(&out.filters, WfpAction::Block, NARROW_IP)
        .next()
        .is_none());
    assert!(
        block_fires(&out.filters, ZONE_ONLY_IP),
        "the unshared address stays blocked"
    );

    let conflicts = rule_conflicts_from(&out.diagnostics, &rule_book);
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    let c = &conflicts[0];
    assert_eq!(c.kind, RuleConflictKind::BlockLeaksSharedAddress);
    assert_eq!(c.rule_id, "b-zone");
    assert_eq!(c.rule_value, "example");
    assert_eq!(c.ip, NARROW_IP.to_string());
    assert_eq!(c.host, ZONE_ONLY_HOST);
    assert_eq!(c.via_host, NARROW_HOST);
    assert_eq!(c.count, 1);
}

/// Positive control for the leak report: an address only the narrow host has
/// yields without leaking anything, so nothing is reported.
#[test]
fn a_block_that_yields_an_unshared_address_reports_no_leak() {
    use nrr_service_runtime::app_enforcement_status::rule_conflicts_from;

    let rule_book = book_with(
        block_rule("b-zone", CanonicalAddressMatch::Zone("example".into())),
        address_rule(
            "r-exact",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        ),
        false,
    );
    let out = codegen_output(&rule_book, &zone_cache());
    assert!(
        rule_conflicts_from(&out.diagnostics, &rule_book).is_empty(),
        "{:?}",
        out.diagnostics
    );
}

/// A literal-IP Block that also names an application cannot be enforced as
/// written, so both mechanisms skip it whole: nothing is blocked for anyone,
/// the route on the same address keeps its permit, no phantom veto is
/// reported, and the skip itself reaches the conflict list.
#[test]
fn an_app_scoped_block_is_skipped_by_both_mechanisms_and_reported() {
    use nrr_domain::rule_shape::UnsupportedShapeReason;
    use nrr_service_runtime::app_enforcement_status::rule_conflicts_from;
    use nrr_shared::ipc_payloads::RuleConflictKind;

    let mut combined = block_rule(
        "b-app-ip",
        CanonicalAddressMatch::ExactIp(IpAddr::V4(NARROW_IP)),
    );
    combined.app_match = app_rule("unused", APP).app_match;
    let rule_book = book_with(
        combined,
        address_rule(
            "r-exact",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        ),
        false,
    );
    let cache = zone_cache();
    let out = codegen_output(&rule_book, &cache);

    assert!(
        covering(&out.filters, WfpAction::Block, NARROW_IP)
            .next()
            .is_none(),
        "codegen widened the app-scoped block to every process"
    );
    assert!(covering(&out.filters, WfpAction::Permit, NARROW_IP)
        .next()
        .is_some());
    assert!(
        !blocked_by_planner(&rule_book, &cache, NARROW_IP),
        "the planner widened the app-scoped block to every process"
    );

    let (_, report) = plan_route_rules(
        &rule_book,
        "S-1-5-21-TEST",
        RouteBehaviorMode::PreferPrimary,
        &PlannerInput {
            ipv6: nrr_service_runtime::enforcement_planner::Ipv6Guard::Off,
            fqdn_cache: &cache,
            app_resolver: &MockAppPathResolver::new(),
            app_observations: &MockAppObservationLookup::new(),
            zone_priority_over_ip: false,
            secondary_ip_denylist: &HashSet::new(),
            packet_blocks: true,
        },
    );
    assert_eq!(
        report.unsupported_shapes(),
        vec![(
            "b-app-ip".to_string(),
            UnsupportedShapeReason::AppScopedDestinationBlock
        )]
    );

    let conflicts = rule_conflicts_from(&out.diagnostics, &rule_book);
    assert_eq!(conflicts.len(), 1, "{conflicts:?}");
    let c = &conflicts[0];
    assert_eq!(c.kind, RuleConflictKind::UnsupportedRuleShape);
    assert_eq!(c.rule_id, "b-app-ip");
    assert_eq!(c.rule_value, NARROW_IP.to_string());
    assert_eq!(c.app, APP);
    assert!(c.ip.is_empty() && c.count == 0);
}

/// The Overlaps screen lists the same conflicts whichever mechanism planned
/// the rules: Windows reads them off the codegen, every other platform off the
/// neutral planner.
#[test]
fn the_planner_reports_the_conflicts_the_codegen_reports() {
    use nrr_service_runtime::app_enforcement_status::rule_conflicts_from;
    use nrr_service_runtime::rule_conflicts::rule_conflict_dtos;
    use nrr_shared::ipc_payloads::RuleConflictKind;

    let shared_cache = || {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(NARROW_HOST, vec![NARROW_IP]);
        cache.set_ips(ZONE_ONLY_HOST, vec![NARROW_IP, ZONE_ONLY_IP]);
        cache
    };
    let literal_block = || {
        block_rule(
            "b-ip",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(NARROW_IP)),
        )
    };
    let zone_block = || block_rule("b-zone", CanonicalAddressMatch::Zone("example".into()));
    let exact_route = || {
        address_rule(
            "r-exact",
            CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
        )
    };
    let mut app_scoped = block_rule(
        "b-app-ip",
        CanonicalAddressMatch::ExactIp(IpAddr::V4(ZONE_ONLY_IP)),
    );
    app_scoped.app_match = app_rule("unused", APP).app_match;
    let several = CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(vec![zone_block(), app_scoped.clone()]),
        secondary: CanonicalRuleSet::from_rules(vec![
            literal_block(),
            address_rule(
                "r-suffix",
                CanonicalAddressMatch::SuffixDomain(NARROW_HOST.into()),
            ),
        ]),
    };

    use RuleConflictKind::*;
    let cases = [
        (
            "literal veto, block on main",
            book_with(literal_block(), exact_route(), true),
            zone_cache(),
            vec![LiteralBlockOverridesRoute],
        ),
        (
            "literal veto, block on additional",
            book_with(literal_block(), exact_route(), false),
            zone_cache(),
            vec![LiteralBlockOverridesRoute],
        ),
        (
            "leak through a shared address",
            book_with(zone_block(), exact_route(), false),
            shared_cache(),
            vec![BlockLeaksSharedAddress],
        ),
        (
            "unsupported shape",
            book_with(app_scoped, exact_route(), false),
            zone_cache(),
            vec![UnsupportedRuleShape],
        ),
        (
            "several, in rule order",
            several,
            shared_cache(),
            vec![
                BlockLeaksSharedAddress,
                UnsupportedRuleShape,
                LiteralBlockOverridesRoute,
            ],
        ),
        (
            "no conflict",
            book_with(zone_block(), exact_route(), false),
            zone_cache(),
            vec![],
        ),
    ];
    for (how, rule_book, cache, kinds) in cases {
        let windows =
            rule_conflicts_from(&codegen_output(&rule_book, &cache).diagnostics, &rule_book);
        let (_, report) = plan_route_rules(
            &rule_book,
            "S-1-5-21-TEST",
            RouteBehaviorMode::PreferPrimary,
            &PlannerInput {
                ipv6: nrr_service_runtime::enforcement_planner::Ipv6Guard::Off,
                fqdn_cache: &cache,
                app_resolver: &MockAppPathResolver::new(),
                app_observations: &MockAppObservationLookup::new(),
                zone_priority_over_ip: false,
                secondary_ip_denylist: &HashSet::new(),
                packet_blocks: true,
            },
        );
        assert_eq!(
            windows.iter().map(|c| c.kind).collect::<Vec<_>>(),
            kinds,
            "{how}: {windows:?}"
        );
        assert_eq!(
            rule_conflict_dtos(&report.conflicts, &rule_book),
            windows,
            "{how}"
        );
    }
}

// ── Networks: every mechanism reaches the engine's answer ──────────────────
//
// A subnet filter covers every address inside it, so a narrower rule inside a
// network is carved out of the network's filters rather than outweighing them.
// These sweeps hold each mechanism's effective verdict, per sample address, to
// `match_sample`.

use nrr_domain::rule_shape::RuleShapeSupport;
use nrr_shared::ip_block::{IpBlock, IpRange};
use nrr_shared::RouteRole;

/// What enforcement carries once routes and Fail-Closed carry networks too.
const NETWORKS: RuleShapeSupport = RuleShapeSupport {
    app_scoped_destination_block: false,
    app_scoped_destination_route: false,
    network_destination: true,
};

/// The rule bands' floors, from the crate-private `wfp_bands`: which route set
/// a winning permit belongs to is its band.
const BASE_PRIMARY: u64 = 0x0020_0000;
const BASE_SECONDARY: u64 = 0x0010_0000;

/// A planner principal the platform under test can lower.
const PLAN_SID: &str = if cfg!(windows) {
    "S-1-5-21-TEST"
} else {
    "unix:uid:1000"
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Route(RouteRole),
    Block,
    Default,
}

fn net_rule(id: &str, text: &str, action: RuleAction) -> CanonicalRule {
    CanonicalRule {
        action,
        ..address_rule(
            id,
            CanonicalAddressMatch::Subnet(IpBlock::parse(text).expect("valid subnet")),
        )
    }
}

fn range_rule(id: &str, first: &str, last: &str) -> CanonicalRule {
    address_rule(
        id,
        CanonicalAddressMatch::ip_range(
            IpRange::new(
                first.parse().expect("valid address"),
                last.parse().expect("valid address"),
            )
            .expect("valid range"),
        ),
    )
}

fn literal(id: &str, ip: &str, action: RuleAction) -> CanonicalRule {
    CanonicalRule {
        action,
        ..address_rule(
            id,
            CanonicalAddressMatch::ExactIp(ip.parse().expect("valid address")),
        )
    }
}

fn engine_outcome(rule_book: &CanonicalRuleBook, host: Option<&str>, ip: IpAddr) -> Outcome {
    use nrr_domain::decision_matching::{RequestedRouteDecision, ZonePriorityPolicy};
    match nrr_domain::decision_engine_input::match_sample(
        rule_book,
        host,
        Some(ip),
        None,
        ZonePriorityPolicy::default(),
        RouteBehaviorMode::PreferPrimary,
    ) {
        RequestedRouteDecision::MatchedRoute { candidate } => match candidate.action {
            RuleAction::Block => Outcome::Block,
            RuleAction::Route | RuleAction::Verify => Outcome::Route(candidate.route_role),
        },
        RequestedRouteDecision::DefaultRoute { .. } => Outcome::Default,
    }
}

fn spec_covers(f: &Spec, ip: IpAddr) -> bool {
    let in_subnet = |net: IpAddr, len: u8| IpBlock::new(net, len).is_some_and(|b| b.contains(ip));
    match ip {
        IpAddr::V4(v4) => {
            f.covers_v4(v4)
                || f.remote_subnet
                    .is_some_and(|(net, len)| in_subnet(IpAddr::V4(net), len))
        }
        IpAddr::V6(v6) => {
            f.covers_v6(v6)
                || f.remote_subnet_v6
                    .is_some_and(|(net, len)| in_subnet(IpAddr::V6(net), len))
        }
    }
}

/// The connect-layer filter that decides `ip`: the highest weight covering it.
fn filter_outcome(filters: &[Spec], ip: IpAddr) -> Outcome {
    use nrr_platform_api::types::WfpLayerKey;
    let winner = filters
        .iter()
        .filter(|f| {
            matches!(
                f.layer,
                WfpLayerKey::AleAuthConnectV4 | WfpLayerKey::AleAuthConnectV6
            )
        })
        .filter(|f| spec_covers(f, ip))
        .max_by_key(|f| f.weight);
    match winner {
        None => Outcome::Default,
        Some(f) if f.action == WfpAction::Block => Outcome::Block,
        Some(f) if f.weight >= BASE_PRIMARY => Outcome::Route(RouteRole::Primary),
        Some(f) => {
            assert!(
                f.weight >= BASE_SECONDARY,
                "a rule permit below the rule bands: {f:?}"
            );
            Outcome::Route(RouteRole::Secondary)
        }
    }
}

fn flow_covers(dst: nrr_platform_api::enforcement::DstMatch, ip: IpAddr) -> bool {
    use nrr_platform_api::enforcement::DstMatch;
    match dst {
        DstMatch::Any => true,
        DstMatch::HostV4(h) => ip == IpAddr::V4(h),
        DstMatch::HostV6(h) => ip == IpAddr::V6(h),
        DstMatch::SubnetV4 { net, prefix } => {
            IpBlock::new(IpAddr::V4(net), prefix).is_some_and(|b| b.contains(ip))
        }
        DstMatch::SubnetV6 { net, prefix } => {
            IpBlock::new(IpAddr::V6(net), prefix).is_some_and(|b| b.contains(ip))
        }
    }
}

/// The neutral plan's winner for `ip`, by the precedence both lowerings realise.
fn plan_outcome(flows: &[nrr_platform_api::enforcement::FlowRule], ip: IpAddr) -> Outcome {
    use nrr_platform_api::enforcement::{PrecedenceClass, Verdict};
    let mut winner: Option<&nrr_platform_api::enforcement::FlowRule> = None;
    for flow in flows.iter().filter(|f| flow_covers(f.flow.dst, ip)) {
        if winner.is_none_or(|w| flow.precedence.is_higher_priority_than(w.precedence)) {
            winner = Some(flow);
        }
    }
    match winner {
        None => Outcome::Default,
        Some(f) if f.verdict == Verdict::Block => Outcome::Block,
        Some(f) => match f.precedence.class {
            PrecedenceClass::RouteRule(role) => Outcome::Route(role),
            other => panic!("a rule permit outside the rule bands: {other:?}"),
        },
    }
}

/// nftables evaluates top-down and stops at the first terminal rule.
#[cfg(not(windows))]
fn nft_outcome(flows: &[nrr_platform_api::enforcement::FlowRule], ip: IpAddr) -> Outcome {
    use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};
    use nrr_platform_linux::lower_linux::{lower_plan, EgressNames};
    use nrr_platform_linux::nft_ir::NftMatch;
    let lowered = lower_plan(
        &EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows: flows.to_vec(),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        },
        &EgressNames::default(),
    );
    assert!(lowered.unsupported.is_empty(), "{:?}", lowered.unsupported);
    let in_net =
        |net: IpAddr, prefix: u8| IpBlock::new(net, prefix).is_some_and(|b| b.contains(ip));
    let first = lowered.ruleset.rules.iter().find(|rule| {
        rule.matches.iter().all(|m| match m {
            NftMatch::DstV4 { net, prefix } => in_net(IpAddr::V4(*net), *prefix),
            NftMatch::DstV6 { net, prefix } => in_net(IpAddr::V6(*net), *prefix),
            NftMatch::DstSetV4(blocks) | NftMatch::DstSetV6(blocks) => {
                blocks.iter().any(|b| b.contains(ip))
            }
            NftMatch::SkUid(_) => true,
            _ => false,
        })
    });
    match first {
        None => Outcome::Default,
        Some(rule) if rule.verdict.is_drop() => Outcome::Block,
        Some(rule) if rule.comment.starts_with("route-primary") => {
            Outcome::Route(RouteRole::Primary)
        }
        Some(rule) if rule.comment.starts_with("route-secondary") => {
            Outcome::Route(RouteRole::Secondary)
        }
        Some(rule) => panic!("an accept outside the rule bands: {rule:?}"),
    }
}

/// The Windows lowering of the neutral plan, read like the codegen.
#[cfg(windows)]
fn lowered_outcome(flows: &[nrr_platform_api::enforcement::FlowRule], ip: IpAddr) -> Outcome {
    use nrr_platform_api::enforcement::{EnforcementPlan, UserPrincipal};
    let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&EnforcementPlan {
        principal: UserPrincipal::from_windows_sid(PLAN_SID).expect("valid sid"),
        flows: flows.to_vec(),
        routes: Vec::new(),
        policy_rules: Vec::new(),
    });
    filter_outcome(&lowered, ip)
}

struct NetworkCase {
    how: &'static str,
    rule_book: CanonicalRuleBook,
    cache: MockFqdnCacheLookup,
    samples: Vec<(Option<&'static str>, &'static str, Outcome)>,
}

fn network_cases() -> Vec<NetworkCase> {
    use Outcome::{Block, Default, Route};
    use RouteRole::{Primary as Main, Secondary as Tunnel};
    let named_cache = || {
        let cache = MockFqdnCacheLookup::new();
        cache.set_ips(NARROW_HOST, vec![NARROW_IP]);
        cache.set_ips(ZONE_ONLY_HOST, vec![ZONE_ONLY_IP]);
        cache
    };
    let book = |primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>| CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    };
    let none = MockFqdnCacheLookup::new;
    vec![
        NetworkCase {
            how: "a tunnel address inside a main network",
            rule_book: book(
                vec![net_rule("p-net", "10.0.0.0/8", RuleAction::Route)],
                vec![literal("s-ip", "10.1.2.3", RuleAction::Route)],
            ),
            cache: none(),
            samples: vec![
                (None, "10.1.2.3", Route(Tunnel)),
                (None, "10.1.2.4", Route(Main)),
                (None, "10.200.0.1", Route(Main)),
                (None, "11.0.0.1", Default),
            ],
        },
        NetworkCase {
            how: "a main address inside a tunnel network",
            rule_book: book(
                vec![literal("p-ip", "10.1.2.3", RuleAction::Route)],
                vec![net_rule("s-net", "10.0.0.0/8", RuleAction::Route)],
            ),
            cache: none(),
            samples: vec![
                (None, "10.1.2.3", Route(Main)),
                (None, "10.1.2.4", Route(Tunnel)),
            ],
        },
        NetworkCase {
            how: "nested prefixes alternating links, main outermost",
            rule_book: book(
                vec![
                    net_rule("p-16", "10.1.0.0/16", RuleAction::Route),
                    net_rule("p-28", "10.1.2.16/28", RuleAction::Route),
                ],
                vec![net_rule("s-24", "10.1.2.0/24", RuleAction::Route)],
            ),
            cache: none(),
            samples: vec![
                (None, "10.1.2.17", Route(Main)),
                (None, "10.1.2.5", Route(Tunnel)),
                (None, "10.1.3.1", Route(Main)),
            ],
        },
        NetworkCase {
            how: "nested prefixes alternating links, tunnel outermost",
            rule_book: book(
                vec![net_rule("p-24", "10.1.2.0/24", RuleAction::Route)],
                vec![
                    net_rule("s-16", "10.1.0.0/16", RuleAction::Route),
                    net_rule("s-28", "10.1.2.16/28", RuleAction::Route),
                ],
            ),
            cache: none(),
            samples: vec![
                (None, "10.1.2.17", Route(Tunnel)),
                (None, "10.1.2.5", Route(Main)),
                (None, "10.1.3.1", Route(Tunnel)),
            ],
        },
        NetworkCase {
            how: "a range inside a network of the other link",
            rule_book: book(
                vec![net_rule("p-24", "10.1.2.0/24", RuleAction::Route)],
                vec![range_rule("s-range", "10.1.2.5", "10.1.2.40")],
            ),
            cache: none(),
            samples: vec![
                (None, "10.1.2.5", Route(Tunnel)),
                (None, "10.1.2.9", Route(Tunnel)),
                (None, "10.1.2.40", Route(Tunnel)),
                (None, "10.1.2.41", Route(Main)),
                (None, "10.1.2.4", Route(Main)),
            ],
        },
        NetworkCase {
            how: "a named host inside a network blocked on the main link",
            rule_book: book(
                vec![net_rule("b-net", "192.0.2.0/24", RuleAction::Block)],
                vec![address_rule(
                    "s-name",
                    CanonicalAddressMatch::ExactFqdn(NARROW_HOST.into()),
                )],
            ),
            cache: named_cache(),
            samples: vec![
                (Some(NARROW_HOST), "192.0.2.10", Route(Tunnel)),
                (None, "192.0.2.21", Block),
            ],
        },
        NetworkCase {
            how: "a named host inside a network blocked on the tunnel",
            rule_book: book(
                vec![address_rule(
                    "p-name",
                    CanonicalAddressMatch::SuffixDomain(NARROW_HOST.into()),
                )],
                vec![net_rule("b-net", "192.0.2.0/24", RuleAction::Block)],
            ),
            cache: named_cache(),
            samples: vec![
                (Some(NARROW_HOST), "192.0.2.10", Route(Main)),
                (None, "192.0.2.21", Block),
            ],
        },
        NetworkCase {
            // A network is narrower than a zone: its Block holds.
            how: "a zone host inside a blocked network",
            rule_book: book(
                vec![net_rule("b-net", "192.0.2.0/24", RuleAction::Block)],
                vec![address_rule(
                    "s-zone",
                    CanonicalAddressMatch::Zone("example".into()),
                )],
            ),
            cache: named_cache(),
            samples: vec![(Some(ZONE_ONLY_HOST), "192.0.2.20", Block)],
        },
        NetworkCase {
            how: "a blocked network inside a route network",
            rule_book: book(
                vec![net_rule("p-net", "10.0.0.0/8", RuleAction::Route)],
                vec![net_rule("b-16", "10.1.0.0/16", RuleAction::Block)],
            ),
            cache: none(),
            samples: vec![(None, "10.1.0.1", Block), (None, "10.2.0.1", Route(Main))],
        },
        NetworkCase {
            how: "a route network inside a blocked one",
            rule_book: book(
                vec![net_rule("b-net", "10.0.0.0/8", RuleAction::Block)],
                vec![net_rule("s-16", "10.1.0.0/16", RuleAction::Route)],
            ),
            cache: none(),
            samples: vec![(None, "10.1.0.1", Route(Tunnel)), (None, "10.2.0.1", Block)],
        },
        NetworkCase {
            how: "a literal Block inside a route network",
            rule_book: book(
                vec![net_rule("p-net", "10.0.0.0/8", RuleAction::Route)],
                vec![literal("b-ip", "10.1.2.3", RuleAction::Block)],
            ),
            cache: none(),
            samples: vec![(None, "10.1.2.3", Block), (None, "10.1.2.4", Route(Main))],
        },
        NetworkCase {
            how: "a network Block ties a route network of the same prefix",
            rule_book: book(
                vec![net_rule("p-net", "10.1.0.0/16", RuleAction::Route)],
                vec![net_rule("b-net", "10.1.0.0/16", RuleAction::Block)],
            ),
            cache: none(),
            samples: vec![(None, "10.1.0.1", Block)],
        },
        NetworkCase {
            how: "an IPv6 main address inside a tunnel network",
            rule_book: book(
                vec![literal("p-ip6", "2001:db8::1", RuleAction::Route)],
                vec![net_rule("s-net6", "2001:db8::/32", RuleAction::Route)],
            ),
            cache: none(),
            samples: vec![
                (None, "2001:db8::1", Route(Main)),
                (None, "2001:db8::2", Route(Tunnel)),
                (None, "2001:db9::1", Default),
            ],
        },
    ]
}

#[test]
fn every_mechanism_gives_a_network_rule_the_engines_answer() {
    for case in network_cases() {
        let filters = generate_filters_with_shapes(
            CodegenInput {
                sid: "S-1-5-21-TEST",
                rule_book: &case.rule_book,
                behavior_mode: RouteBehaviorMode::PreferPrimary,
                fqdn_cache: &case.cache,
                app_observations: &MockAppObservationLookup::new(),
                app_resolver: &MockAppPathResolver::new(),
                secondary_ip_denylist: &HashSet::new(),
                zone_priority_over_ip: false,
                families: nrr_service_runtime::enforcement_planner::FamilyScope::Both,
                packet_blocks: true,
            },
            NETWORKS,
        )
        .filters;
        let flows = plan_route_rules_with_shapes(
            &case.rule_book,
            PLAN_SID,
            RouteBehaviorMode::PreferPrimary,
            &PlannerInput {
                ipv6: nrr_service_runtime::enforcement_planner::Ipv6Guard::FiltersAndRoutes,
                fqdn_cache: &case.cache,
                app_resolver: &MockAppPathResolver::new(),
                app_observations: &MockAppObservationLookup::new(),
                zone_priority_over_ip: false,
                secondary_ip_denylist: &HashSet::new(),
                packet_blocks: true,
            },
            NETWORKS,
        )
        .0;
        for (host, ip, expected) in &case.samples {
            let ip: IpAddr = ip.parse().expect("valid sample");
            let how = case.how;
            assert_eq!(
                engine_outcome(&case.rule_book, *host, ip),
                *expected,
                "{how}: the case misstates the engine for {ip}",
            );
            assert_eq!(
                filter_outcome(&filters, ip),
                *expected,
                "{how}: codegen, {ip}"
            );
            assert_eq!(plan_outcome(&flows, ip), *expected, "{how}: planner, {ip}");
            #[cfg(windows)]
            assert_eq!(
                lowered_outcome(&flows, ip),
                *expected,
                "{how}: Windows lowering, {ip}"
            );
            #[cfg(not(windows))]
            assert_eq!(nft_outcome(&flows, ip), *expected, "{how}: nftables, {ip}");
        }
    }
}

/// Positive control for the sweep: an uncarved main network outranks the
/// tunnel host inside it, and the reading must say so.
#[test]
fn the_network_sweep_notices_a_network_that_swallows_a_narrower_host() {
    let net = Spec {
        layer: nrr_platform_api::types::WfpLayerKey::AleAuthConnectV4,
        action: WfpAction::Permit,
        remote_ip: None,
        remote_ip_set: Vec::new(),
        remote_ip_set_v6: Vec::new(),
        remote_port: None,
        weight: BASE_PRIMARY,
        id: nrr_platform_api::types::WfpFilterId { raw: 1 },
        user_sid: None,
        app_pattern: None,
        local_interface_luid: None,
        remote_subnet: Some((Ipv4Addr::new(10, 0, 0, 0), 8)),
        remote_subnet_v6: None,
        ip_protocol: None,
    };
    let host = Spec {
        remote_subnet: None,
        remote_ip: Some(Ipv4Addr::new(10, 1, 2, 3)),
        weight: BASE_SECONDARY,
        id: nrr_platform_api::types::WfpFilterId { raw: 2 },
        ..net.clone()
    };
    assert_eq!(
        filter_outcome(&[net, host], "10.1.2.3".parse().expect("ip")),
        Outcome::Route(RouteRole::Primary)
    );
}
