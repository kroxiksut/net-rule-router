use super::*;

/// Fixture helper: a v4 address as the cache now stores it.
fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}
use nrr_domain::canonical::{CanonicalRule, CanonicalRuleSet};
use nrr_domain::RuleId;
use std::collections::HashMap;

fn rule(id: &str, m: CanonicalAddressMatch, action: RuleAction) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: Some(m),
        app_match: None,
        comment: String::new(),
        action,
        origin: None,
    }
}

fn exact_ip_rule(id: &str, addr: Ipv4Addr) -> CanonicalRule {
    rule(
        id,
        CanonicalAddressMatch::ExactIp(IpAddr::V4(addr)),
        RuleAction::Route,
    )
}

fn book(primary: Vec<CanonicalRule>, secondary: Vec<CanonicalRule>) -> CanonicalRuleBook {
    CanonicalRuleBook {
        primary: CanonicalRuleSet::from_rules(primary),
        secondary: CanonicalRuleSet::from_rules(secondary),
    }
}

/// In-memory cache mock (host→IPs, suffix→subdomains) for the fan-out tests.
#[derive(Default)]
struct MapCache {
    hosts: HashMap<String, Vec<IpAddr>>,
    suffixes: HashMap<String, Vec<String>>,
}
impl FqdnCacheLookup for MapCache {
    fn ips_for_hostname(&self, h: &str) -> Vec<IpAddr> {
        self.hosts.get(h).cloned().unwrap_or_default()
    }
    fn hostnames_under_suffix(&self, s: &str, _limit: usize) -> Vec<String> {
        self.suffixes.get(s).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
struct MapResolver(HashMap<String, Vec<std::path::PathBuf>>);
impl AppPathResolver for MapResolver {
    fn resolve(&self, pat: &str) -> Vec<std::path::PathBuf> {
        self.0.get(pat).cloned().unwrap_or_default()
    }
}

#[derive(Default)]
struct MapObs(HashMap<String, Vec<Ipv4Addr>>);
impl AppObservationLookup for MapObs {
    fn ips_for_app(&self, app: &str) -> Vec<Ipv4Addr> {
        self.0.get(app).cloned().unwrap_or_default()
    }
}

/// A `PlannerInput` from a cache, resolver, and observations.
fn planner_input<'a>(
    cache: &'a MapCache,
    resolver: &'a MapResolver,
    obs: &'a MapObs,
) -> PlannerInput<'a> {
    PlannerInput {
        ipv6: Ipv6Guard::Off,
        secondary_ip_denylist: NO_DENYLIST.get_or_init(HashSet::new),
        fqdn_cache: cache,
        app_resolver: resolver,
        app_observations: obs,
        zone_priority_over_ip: false,
    }
}

/// The shared-IP policy decides what the tunnel may claim, and the plan has
/// to be built behind that decision — the Windows codegen reads a
/// denylist-filtered cache for secondary rules and the raw one for primary.
/// Planning without it put declined addresses back on the tunnel, and
/// shifted every ordinal after them, which is what made the live and
/// neutral pipelines disagree on real data.
#[test]
fn a_declined_shared_address_is_kept_off_the_tunnel() {
    let shared = Ipv4Addr::new(203, 0, 113, 7);
    let own = Ipv4Addr::new(203, 0, 113, 8);
    let cache = MapCache {
        hosts: HashMap::from([(
            "site.test".to_string(),
            vec![IpAddr::V4(shared), IpAddr::V4(own)],
        )]),
        suffixes: HashMap::new(),
    };
    let resolver = MapResolver::default();
    let obs = MapObs::default();
    let declined: HashSet<Ipv4Addr> = HashSet::from([shared]);
    // One rule, on the additional route: the policy is about what the
    // TUNNEL may claim. (A main-link rule naming the same host would settle
    // the address by ownership instead, which is a different mechanism.)
    let rule_book = book(
        Vec::new(),
        vec![rule(
            "r-2",
            CanonicalAddressMatch::ExactFqdn("site.test".into()),
            RuleAction::Route,
        )],
    );

    let planned = |denylist: &HashSet<Ipv4Addr>| -> Vec<(RouteRole, Ipv4Addr)> {
        let input = PlannerInput {
            ipv6: Ipv6Guard::Off,
            fqdn_cache: &cache,
            app_resolver: &resolver,
            app_observations: &obs,
            zone_priority_over_ip: false,
            secondary_ip_denylist: denylist,
        };
        plan_route_rules(
            &rule_book,
            "S-1-5-21-DENY",
            RouteBehaviorMode::PreferPrimary,
            &input,
        )
        .0
        .into_iter()
        .filter_map(|f| match (f.precedence.class, f.flow.dst) {
            (PrecedenceClass::RouteRule(role), DstMatch::HostV4(ip)) => Some((role, ip)),
            _ => None,
        })
        .collect()
    };

    let with_policy = planned(&declined);
    assert!(
        !with_policy.contains(&(RouteRole::Secondary, shared)),
        "the tunnel must not claim an address the policy declined: {with_policy:?}",
    );
    assert!(with_policy.contains(&(RouteRole::Secondary, own)));

    // Positive control: without the denylist the tunnel claims it, which is
    // exactly the plan the live pipeline does NOT produce.
    let without_policy = planned(&HashSet::new());
    assert!(without_policy.contains(&(RouteRole::Secondary, shared)));
}

fn app_rule(id: &str, pattern: &str, action: RuleAction) -> CanonicalRule {
    CanonicalRule {
        id: RuleId(id.into()),
        enabled: true,
        address_match: None,
        app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
            pattern: CanonicalAppPattern::Exact(pattern.into()),
            include_child_processes: false,
        }),
        comment: String::new(),
        action,
        origin: None,
    }
}

/// A Linux principal must survive planning. Parsing the partition key as a
/// Windows SID silently produced an UNSCOPED rule, and unscoped means "every
/// user on this machine" — one user's routing policy would have governed
/// everyone else's traffic.
#[test]
fn a_unix_principal_scopes_the_flows_it_plans() {
    let rb = book(
        vec![exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1))],
        vec![],
    );
    let (cache, resolver, obs) = (
        MapCache::default(),
        MapResolver::default(),
        MapObs::default(),
    );
    let flows = plan_route_rules(
        &rb,
        "unix:uid:1000",
        RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &resolver, &obs),
    )
    .0;

    assert!(!flows.is_empty(), "the rule must plan at least one flow");
    for flow in &flows {
        let scoped = flow
            .principal
            .0
            .as_ref()
            .and_then(|p| p.as_unix_uid())
            .expect("every flow must carry the uid it was planned for");
        assert_eq!(scoped, 1000);
    }
}

/// The baseline belongs to no user, so it plans unscoped on purpose — the
/// one case where a missing principal is the answer rather than a bug.
#[test]
fn the_baseline_plans_without_a_principal() {
    let rb = book(
        vec![exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1))],
        vec![],
    );
    let (cache, resolver, obs) = (
        MapCache::default(),
        MapResolver::default(),
        MapObs::default(),
    );
    let flows = plan_route_rules(
        &rb,
        nrr_domain::user_principal::BASELINE_PRINCIPAL,
        RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &resolver, &obs),
    )
    .0;

    assert!(!flows.is_empty());
    assert!(flows.iter().all(|f| f.principal.0.is_none()));
}

#[test]
fn plans_exact_ip_permits_primary_then_secondary_with_slot_ordinals() {
    let rb = book(
        vec![
            exact_ip_rule("p-0", Ipv4Addr::new(203, 0, 113, 1)),
            exact_ip_rule("p-1", Ipv4Addr::new(203, 0, 113, 2)),
        ],
        vec![exact_ip_rule("s-0", Ipv4Addr::new(198, 51, 100, 9))],
    );
    let flows = plan_route_rules(
        &rb,
        "S-1-5-21-A",
        RouteBehaviorMode::PreferPrimary,
        &planner_input(
            &MapCache::default(),
            &MapResolver::default(),
            &MapObs::default(),
        ),
    )
    .0;
    assert_eq!(flows.len(), 3);
    assert_eq!(
        flows[0].precedence.class,
        PrecedenceClass::RouteRule(RouteRole::Primary)
    );
    assert_eq!(flows[0].precedence.ordinal, 0);
    assert_eq!(flows[1].precedence.ordinal, SLOTS_PER_RULE);
    assert_eq!(
        flows[2].precedence.class,
        PrecedenceClass::RouteRule(RouteRole::Secondary)
    );
    assert_eq!(flows[2].precedence.ordinal, 0);
    assert_eq!(
        flows[0].principal.0.as_ref().map(|p| p.as_stored()),
        Some("S-1-5-21-A")
    );
    assert!(flows.iter().all(|f| f.verdict == Verdict::Permit));
}

#[test]
fn plans_fqdn_fanout_and_block() {
    let mut cache = MapCache::default();
    cache.hosts.insert(
        "api.example.com".into(),
        vec![v4(203, 0, 113, 1), v4(203, 0, 113, 2)],
    );
    let rb = book(
        vec![rule(
            "p-fqdn",
            CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
            RuleAction::Route,
        )],
        vec![rule(
            "s-block",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            RuleAction::Block,
        )],
    );
    let flows = plan_route_rules(
        &rb,
        "S-1-5-21-A",
        RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &MapResolver::default(), &MapObs::default()),
    )
    .0;
    // Two fan-out permits (ordinals 0,1) + one block flow.
    assert_eq!(flows.len(), 3);
    assert_eq!(flows[0].precedence.ordinal, 0);
    assert_eq!(flows[1].precedence.ordinal, 1);
    assert!(flows[..2].iter().all(|f| f.verdict == Verdict::Permit));
    let blk = &flows[2];
    assert_eq!(blk.verdict, Verdict::Block);
    assert_eq!(blk.precedence.class, PrecedenceClass::HardBlock);
    assert_eq!(blk.coverage, Coverage::AllPackets);
}

/// An IPv6 exact-address rule is named only when a link carries the family;
/// under `Off` the plan is exactly what it was before the rule existed.
#[test]
fn an_ipv6_exact_address_rule_is_planned_only_when_a_link_carries_ipv6() {
    let v6: std::net::Ipv6Addr = "2001:db8::7".parse().expect("v6");
    let rb = book(
        vec![],
        vec![rule(
            "s-v6",
            CanonicalAddressMatch::ExactIp(IpAddr::V6(v6)),
            RuleAction::Route,
        )],
    );
    let cache = MapCache::default();
    let resolver = MapResolver::default();
    let obs = MapObs::default();

    let off = planner_input(&cache, &resolver, &obs);
    let (flows, _) = plan_route_rules(&rb, "S-1-5-21-A", RouteBehaviorMode::PreferPrimary, &off);
    assert!(flows.is_empty(), "{flows:?}");

    let carried = PlannerInput {
        ipv6: Ipv6Guard::FiltersAndRoutes,
        ..planner_input(&cache, &resolver, &obs)
    };
    let (flows, _) = plan_route_rules(
        &rb,
        "S-1-5-21-A",
        RouteBehaviorMode::PreferPrimary,
        &carried,
    );
    assert!(
        flows.iter().any(|f| f.flow.dst == DstMatch::HostV6(v6)),
        "{flows:?}"
    );
}

#[test]
fn skips_disabled_and_unresolved_rules() {
    let mut disabled = exact_ip_rule("d", Ipv4Addr::new(10, 0, 0, 1));
    disabled.enabled = false;
    // An app rule with no resolved exe/observed IP → no flow (like the
    // current codegen's diagnostic-only path).
    let app = app_rule("a", "notinstalled.exe", RuleAction::Route);
    // A cold-cache ExactFqdn resolves to nothing → no flow.
    let cold = rule(
        "f",
        CanonicalAddressMatch::ExactFqdn("uncached.example".into()),
        RuleAction::Route,
    );
    let rb = book(vec![disabled, app, cold], vec![]);
    assert!(plan_route_rules(
        &rb,
        "S-1-5-21-A",
        RouteBehaviorMode::PreferPrimary,
        &planner_input(
            &MapCache::default(),
            &MapResolver::default(),
            &MapObs::default()
        )
    )
    .0
    .is_empty());
}

// ── EQUIVALENCE — route rules (Windows only) ─────────────────────────────────
// The neutral pipeline `plan_route_rules` → `lower_windows::lower_route_rules`
// must produce the SAME enforcement as today's `wfp_codegen::generate_filters`
// for the full rule-driven surface (ExactIp + ExactFqdn/Suffix fan-out + Block
// + Application: per-exe ALE_APP_ID filters and observed-dest /32s), checked
// by the behavioral oracle (weights/ids ignored, arbitration order preserved).
// `lower_windows` lives in the Windows backend → this proof is `#[cfg(windows)]`.
#[cfg(windows)]
#[test]
fn slices123_neutral_pipeline_matches_current_codegen() {
    use crate::wfp_codegen::{generate_filters, CodegenInput};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let mut cache = MapCache::default();
    cache.hosts.insert(
        "api.example.com".into(),
        vec![v4(203, 0, 113, 1), v4(203, 0, 113, 2)],
    );
    cache.suffixes.insert(
        "corp.example".into(),
        vec!["a.corp.example".into(), "b.corp.example".into()],
    );
    cache
        .hosts
        .insert("a.corp.example".into(), vec![v4(198, 51, 100, 1)]);
    cache
        .hosts
        .insert("b.corp.example".into(), vec![v4(198, 51, 100, 2)]);

    // App rule: resolves to two exe paths + one observed destination IP.
    let mut resolver = MapResolver::default();
    resolver.0.insert(
        "aiclient.exe".into(),
        vec![
            std::path::PathBuf::from(r"C:\Apps\aiclient.exe"),
            std::path::PathBuf::from(r"C:\Apps2\aiclient.exe"),
        ],
    );
    let mut obs = MapObs::default();
    obs.0
        .insert("aiclient.exe".into(), vec![Ipv4Addr::new(23, 10, 20, 159)]);

    let sid = "S-1-5-21-1-2-3-1001";
    let rb = book(
        vec![
            exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5)),
            rule(
                "p-fqdn",
                CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                RuleAction::Route,
            ),
        ],
        vec![
            rule(
                "s-suffix",
                CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                RuleAction::Route,
            ),
            rule(
                "s-block",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
                RuleAction::Block,
            ),
            app_rule("s-app", "aiclient.exe", RuleAction::Route),
        ],
    );

    let denylist = std::collections::HashSet::new();
    let current = generate_filters(CodegenInput {
        sid,
        rule_book: &rb,
        behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    let plan = EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
            .expect("valid sid"),
        flows: plan_route_rules(
            &rb,
            sid,
            nrr_domain::RouteBehaviorMode::PreferPrimary,
            &planner_input(&cache, &resolver, &obs),
        )
        .0,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

    // 1 ExactIp + 2 fqdn + 2 suffix + (1 ALE block + 1 mirror) + (2 app-id +
    // 1 observed /32) = 10 filters.
    assert_eq!(current.filters.len(), 10, "sanity: ten filters");
    assert!(
        behaviorally_equivalent(&current.filters, &lowered),
        "neutral pipeline must install the SAME filters as the current codegen"
    );
    assert!(
        arbitration_order_preserved(&current.filters, &lowered),
        "neutral pipeline must preserve the arbitration order"
    );
}

// ── EQUIVALENCE — per-destination kill-switch (Windows only) ────────────────
// `plan_kill_switch_destinations` → `lower_windows::lower_kill_switch` must
// produce the SAME leak-proof pins as `killswitch_codegen::kill_switch_filters`
// for the ALE (TCP/UDP) case: each protected IP → a permit(luid) + block pair.
#[cfg(windows)]
#[test]
fn slice4a_kill_switch_matches_current_codegen() {
    use crate::killswitch_codegen::{kill_switch_filters, KillSwitchProtocols};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let luid = 0x1234_5678_u64;
    let ips = [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
    ];
    // TCP/UDP only → ALE pairs, no packet-layer (multi-protocol) pairs.
    let protos = KillSwitchProtocols {
        tcp: true,
        udp: true,
        icmp: false,
        igmp: false,
        gre: false,
        esp: false,
        other: false,
    };
    let current = kill_switch_filters(sid, &ips, luid, protos);

    let plan = EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
            .expect("valid sid"),
        flows: plan_kill_switch_destinations(sid, &ips, protos),
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = nrr_platform_windows::lower_windows::lower_kill_switch(&plan, luid);

    assert_eq!(current.len(), 4, "2 destinations × (permit + block)");
    assert!(
        behaviorally_equivalent(&current, &lowered),
        "kill-switch pins must be behaviourally equivalent"
    );
    assert!(
        arbitration_order_preserved(&current, &lowered),
        "kill-switch permit must still outrank its block"
    );
}

/// The pool is the machinery every fake-routed host is served through, so
/// the neutral pipeline has to reproduce it exactly — including the UDP
/// veto that must sit ABOVE the permit it qualifies. Both switch positions
/// are exercised: with the relay on, the vetoes are absent, and a pipeline
/// that emitted them unconditionally would still pass the off-case alone.
#[cfg(windows)]
#[test]
fn slice6_fake_ip_pool_matches_current_codegen() {
    use crate::killswitch_codegen::fake_ip_pool_permit_filters;
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::fake_ip::FakeIpPoolConfig;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let pool = FakeIpPoolConfig::default();

    for udp_relay_enabled in [false, true] {
        let current = fake_ip_pool_permit_filters(sid, &pool, udp_relay_enabled);
        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_fake_ip_pool(sid, &pool, udp_relay_enabled),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_fake_ip_pool(&plan);

        assert!(
            !current.is_empty(),
            "the pool always permits itself — otherwise this proves nothing"
        );
        assert!(
            behaviorally_equivalent(&current, &lowered),
            "pool filters must match (udp_relay_enabled={udp_relay_enabled}):
current={current:#?}
lowered={lowered:#?}"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "the UDP veto must keep outranking the pool permit"
        );
    }
}

/// The floor under the strict default block. Lowered with NO tunnel LUID
/// on purpose: the floor exists whether or not a tunnel is up, and the
/// posture that needs a LUID (the blanket block and its egress permit) is
/// exactly what must NOT appear in that case.
#[cfg(windows)]
#[test]
fn slice7_default_block_exemptions_match_current_codegen() {
    use crate::killswitch_codegen::{default_block_exemptions, FailClosedExemptions};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let server_ips = vec![Ipv4Addr::new(203, 0, 113, 5)];
    let local_subnets = vec![(Ipv4Addr::new(192, 168, 1, 0), 24)];

    let current = default_block_exemptions(
        sid,
        &FailClosedExemptions {
            bootstrap_server_ips: server_ips.clone(),
            bootstrap_server_ips_v6: Vec::new(),
            local_subnets: local_subnets.clone(),
            local_subnets_v6: Vec::new(),
            foreign_tunnel_luids: Vec::new(),
            ..Default::default()
        },
    );
    assert!(!current.is_empty(), "the floor is never empty");

    let plan = EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
            .expect("valid sid"),
        flows: plan_default_block_exemptions(sid, &server_ips, &local_subnets),
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = nrr_platform_windows::lower_windows::lower_catch_all_kill_switch(&plan, 0);

    assert!(
        behaviorally_equivalent(&current, &lowered),
        "the floor must match:
current={current:#?}
lowered={lowered:#?}"
    );
    assert!(
        arbitration_order_preserved(&current, &lowered),
        "the floor's own order is what the codegen's running weight encodes"
    );
}

/// The kill switch and the GUI do not consume the plan — they consume sets
/// READ BACK off it. Until those sets come from the plan, the live codegen
/// cannot be switched off no matter how equal the filters are.
#[test]
fn slice8_derived_sets_match_current_codegen() {
    use crate::wfp_codegen::{generate_filters, CodegenInput};

    let mut cache = MapCache::default();
    cache.hosts.insert(
        "api.example.com".into(),
        vec![v4(203, 0, 113, 1), v4(203, 0, 113, 2)],
    );
    cache.suffixes.insert(
        "corp.example".into(),
        vec!["a.corp.example".into(), "b.corp.example".into()],
    );
    cache
        .hosts
        .insert("a.corp.example".into(), vec![v4(198, 51, 100, 1)]);
    cache
        .hosts
        .insert("b.corp.example".into(), vec![v4(198, 51, 100, 2)]);
    let mut resolver = MapResolver::default();
    resolver.0.insert(
        "aiclient.exe".into(),
        vec![
            std::path::PathBuf::from(r"C:\Apps\aiclient.exe"),
            std::path::PathBuf::from(r"C:\Apps2\aiclient.exe"),
        ],
    );
    // One of the built-in VPN globs resolves here, so the exemption set is
    // NOT empty — two empty lists would agree about nothing.
    resolver.0.insert(
        "*vpn*".into(),
        vec![std::path::PathBuf::from(
            r"C:\Program Files\Acme VPN\acmevpn.exe",
        )],
    );
    let mut obs = MapObs::default();
    obs.0
        .insert("aiclient.exe".into(), vec![Ipv4Addr::new(23, 10, 20, 159)]);

    let sid = "S-1-5-21-1-2-3-1001";
    let rb = book(
        vec![
            exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5)),
            rule(
                "p-fqdn",
                CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                RuleAction::Route,
            ),
        ],
        vec![
            rule(
                "s-suffix",
                CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                RuleAction::Route,
            ),
            rule(
                "s-block",
                CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
                RuleAction::Block,
            ),
            app_rule("s-app", "aiclient.exe", RuleAction::Route),
        ],
    );
    let denylist = std::collections::HashSet::new();
    let current = generate_filters(CodegenInput {
        sid,
        rule_book: &rb,
        behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let flows = plan_route_rules(
        &rb,
        sid,
        nrr_domain::RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &resolver, &obs),
    )
    .0;

    // Compared as SETS. The shipped order is an artefact of WFP slot
    // packing — the codegen reads its addresses back out of packed chunks,
    // whose bucket order comes from an FNV hash — while the plan keeps them
    // in planning order. Neither order carries policy: these addresses each
    // get their own permit/block pair, and pairs for different destinations
    // never arbitrate against each other. What the switch-over WILL change
    // is the ordinals, hence the literal weights, hence a one-off churn on
    // the first apply after it.
    let sorted = |mut v: Vec<IpAddr>| {
        v.sort_unstable();
        v
    };
    // App observations stay IPv4 on both sides of the comparison.
    let sorted_v4 = |mut v: Vec<Ipv4Addr>| {
        v.sort_unstable();
        v
    };
    assert_eq!(
        sorted(route_destinations(&flows, RouteRole::Secondary)),
        sorted(current.secondary_dest_ips.clone()),
        "the kill switch protects what the tunnel routes"
    );
    assert_eq!(
        sorted(route_destinations(&flows, RouteRole::Primary)),
        sorted(current.primary_dest_ips.clone()),
        "the block-all spares what the main link routes"
    );
    assert_eq!(
        route_app_paths(&flows, RouteRole::Secondary),
        current.secondary_app_patterns,
        "an app the tunnel routes is pinned by its own pair"
    );
    assert_eq!(
        route_app_paths(&flows, RouteRole::Primary),
        current.primary_app_patterns,
        "an app the main link routes is never a leak to cut"
    );
    assert_eq!(
        sorted_v4(app_observed_destinations(&flows, RouteRole::Secondary)),
        sorted_v4(current.app_observed_secondary_ips.clone()),
        "an address learned from watching an app is guarded by that app's pair"
    );
    // Positive control for the ordinal window: the fixture's app rule DOES
    // contribute an observed address, so an empty answer would be a passing
    // test that proves nothing.
    assert_eq!(
        app_observed_destinations(&flows, RouteRole::Secondary),
        vec![Ipv4Addr::new(23, 10, 20, 159)],
    );
    assert_eq!(
        vpn_default_exempt_paths(&resolver),
        current.vpn_default_exempt_paths,
        "the tunnel client's own exemption set is resolved the same way"
    );
    assert!(
        !current.vpn_default_exempt_paths.is_empty(),
        "positive control: the fixture resolves one VPN client"
    );
}

/// The report is the half of the codegen's answer the plan cannot carry: a
/// rule that resolved to nothing emits no flow, and silence reads as "no
/// such rule". Every list here has a fixture behind it — an app that does
/// not resolve, a host nobody cached, a zone with nothing under it and an
/// address both links claim — so an empty report would fail the test.
#[test]
fn slice9_plan_report_matches_current_codegen_diagnostics() {
    use crate::wfp_codegen::{generate_filters, CodegenDiagnostic, CodegenInput};

    let mut cache = MapCache::default();
    cache
        .hosts
        .insert("known.example".into(), vec![v4(203, 0, 113, 9)]);
    let mut resolver = MapResolver::default();
    resolver.0.insert(
        "known.exe".into(),
        vec![std::path::PathBuf::from(r"C:\Apps\known.exe")],
    );
    let mut obs = MapObs::default();
    // The app watched an address the MAIN link's own rule names: the app
    // rule does not take it over, and the user is told which one it was.
    obs.0
        .insert("known.exe".into(), vec![Ipv4Addr::new(203, 0, 113, 9)]);

    let sid = "S-1-5-21-1-2-3-1001";
    let rb = book(
        vec![rule(
            "p-known",
            CanonicalAddressMatch::ExactFqdn("known.example".into()),
            RuleAction::Route,
        )],
        vec![
            rule(
                "s-cold",
                CanonicalAddressMatch::ExactFqdn("cold.example".into()),
                RuleAction::Route,
            ),
            rule(
                "s-zone",
                CanonicalAddressMatch::Zone("empty.zone".into()),
                RuleAction::Route,
            ),
            app_rule("s-missing-app", "ghost.exe", RuleAction::Route),
            app_rule("s-app", "known.exe", RuleAction::Route),
        ],
    );

    let denylist = std::collections::HashSet::new();
    let current = generate_filters(CodegenInput {
        sid,
        rule_book: &rb,
        behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let (_, report) = plan_route_rules(
        &rb,
        sid,
        nrr_domain::RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &resolver, &obs),
    );

    let mut codegen_apps: Vec<String> = Vec::new();
    let mut codegen_hosts: Vec<String> = Vec::new();
    let mut codegen_claimed: Vec<(String, Ipv4Addr)> = Vec::new();
    for diag in &current.diagnostics {
        match diag {
            CodegenDiagnostic::AppUnresolved { app, .. } => codegen_apps.push(app.clone()),
            CodegenDiagnostic::HostnameUnresolved { hostname, .. } => {
                codegen_hosts.push(hostname.clone())
            }
            CodegenDiagnostic::SuffixEmpty { suffix, .. } => codegen_hosts.push(suffix.clone()),
            CodegenDiagnostic::ZoneEmpty { zone, .. } => codegen_hosts.push(zone.clone()),
            CodegenDiagnostic::AppDestinationClaimedByPrimary { app, ip, .. } => {
                codegen_claimed.push((app.clone(), *ip))
            }
            _ => {}
        }
    }

    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    assert_eq!(
        sorted(report.unresolved_apps.clone()),
        sorted(codegen_apps.clone()),
        "an app rule pointing at nothing installed"
    );
    assert_eq!(
        sorted(report.unresolved_hosts.clone()),
        sorted(codegen_hosts.clone()),
        "a rule waiting on DNS, and a zone with nothing under it"
    );
    assert_eq!(
        report.claimed_by_main.clone(),
        codegen_claimed.clone(),
        "an address the main link named is not the app rule's to take"
    );

    // Positive controls: each list is non-empty, so an all-empty report
    // could not pass this test by agreeing about nothing.
    assert_eq!(codegen_apps, vec!["ghost.exe".to_string()]);
    assert_eq!(sorted(codegen_hosts), vec!["cold.example", "empty.zone"]);
    assert_eq!(
        codegen_claimed,
        vec![("known.exe".to_string(), Ipv4Addr::new(203, 0, 113, 9))]
    );
}

/// The two caps in the report. Both are silent truncations in the plan —
/// filters simply stop appearing — so the only place a user can learn that
/// a rule was cut short is this report.
#[test]
fn slice9_plan_report_names_both_caps() {
    use crate::wfp_codegen::{generate_filters, CodegenDiagnostic, CodegenInput};

    let mut cache = MapCache::default();
    // A zone whose fan-out hits the backstop.
    let hosts: Vec<String> = (0..SUFFIX_FANOUT_BACKSTOP)
        .map(|i| format!("h{i}.wide.zone"))
        .collect();
    for (i, h) in hosts.iter().enumerate() {
        cache.hosts.insert(
            h.clone(),
            vec![IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xff) as u8,
                ((i >> 8) & 0xff) as u8,
                (i & 0xff) as u8,
            ))],
        );
    }
    cache.suffixes.insert("wide.zone".into(), hosts);

    // An app resolving to more executables than the fan-out allows.
    let mut resolver = MapResolver::default();
    resolver.0.insert(
        "many.exe".into(),
        (0..(APP_PATH_FANOUT_CAP + 1))
            .map(|i| std::path::PathBuf::from(format!(r"C:\Apps\{i}\many.exe")))
            .collect(),
    );
    let obs = MapObs::default();

    let sid = "S-1-5-21-1-2-3-1001";
    let rb = book(
        Vec::new(),
        vec![
            rule(
                "s-wide",
                CanonicalAddressMatch::Zone("wide.zone".into()),
                RuleAction::Route,
            ),
            app_rule("s-many", "many.exe", RuleAction::Route),
        ],
    );
    let denylist = std::collections::HashSet::new();
    let current = generate_filters(CodegenInput {
        sid,
        rule_book: &rb,
        behavior_mode: nrr_domain::RouteBehaviorMode::PreferPrimary,
        fqdn_cache: &cache,
        app_observations: &obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });
    let (_, report) = plan_route_rules(
        &rb,
        sid,
        nrr_domain::RouteBehaviorMode::PreferPrimary,
        &planner_input(&cache, &resolver, &obs),
    );

    let codegen_truncated: Vec<(String, String, usize)> = current
        .diagnostics
        .iter()
        .filter_map(|d| match d {
            CodegenDiagnostic::SuffixTruncated {
                rule_id,
                suffix,
                cap,
            } => Some((rule_id.clone(), suffix.clone(), *cap)),
            _ => None,
        })
        .collect();
    let codegen_over_capped: Vec<(String, usize, usize)> = current
        .diagnostics
        .iter()
        .filter_map(|d| match d {
            CodegenDiagnostic::AppOverCapped {
                app, cap, resolved, ..
            } => Some((app.clone(), *cap as usize, *resolved)),
            _ => None,
        })
        .collect();

    assert_eq!(report.truncated_suffixes, codegen_truncated);
    assert_eq!(report.over_capped_apps, codegen_over_capped);
    // Positive controls: both caps really fired in this fixture.
    assert_eq!(
        codegen_truncated,
        vec![(
            "s-wide".to_string(),
            "wide.zone".to_string(),
            SUFFIX_FANOUT_BACKSTOP
        )]
    );
    assert_eq!(
        codegen_over_capped,
        vec![(
            "many.exe".to_string(),
            APP_PATH_FANOUT_CAP as usize,
            APP_PATH_FANOUT_CAP as usize + 1
        )]
    );
}

// ── DoH/DoT lockdown on LINUX ───────────────────────────────────────────────
// Windows needs its own `lower_doh_dot_block` because WFP packs addresses
// into OR-condition slots; nftables has no such shape, so the lockdown
// lowers through the ordinary flow path. This test is what says so — the
// generic path was believed to swallow `DohBlock`, and nothing measured it.
#[cfg(not(windows))]
#[test]
fn the_doh_lockdown_lowers_to_nftables_through_the_ordinary_flow_path() {
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_linux::lower_linux::{lower_plan, EgressNames};
    use nrr_platform_linux::nft_ir::{NftMatch, NftVerdict};

    let principal = nrr_platform_api::enforcement::UserPrincipal::from_linux_uid(1000);
    let sid = principal.as_stored().to_string();
    let resolvers = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(77, 88, 8, 8)];
    let plan = EnforcementPlan {
        principal,
        flows: plan_doh_dot_block(&sid, &resolvers, true),
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = lower_plan(
        &plan,
        &EgressNames {
            primary: Some("eth0".into()),
            secondary: Some("nrrtun0".into()),
        },
    );
    assert!(
        lowered.unsupported.is_empty(),
        "no DoH flow may be reported unsupported: {:?}",
        lowered.unsupported
    );

    // Every resolver is cut on 443 for both transports, and the global DoT
    // port is cut for both — the same twelve verdicts the Windows codegen
    // installs, expressed as ten nft rules (the two `Any:853` cuts carry no
    // address).
    let rules = &lowered.ruleset.rules;
    for ip in resolvers {
        for proto in [6u8, 17u8] {
            assert!(
                rules.iter().any(|r| {
                    r.verdict == NftVerdict::Drop
                        && r.comment.starts_with("doh-block#")
                        && r.matches.contains(&NftMatch::DstV4 {
                            net: ip,
                            prefix: 32,
                        })
                        && r.matches.contains(&NftMatch::Protocol(proto))
                        && r.matches.contains(&NftMatch::DstPort(443))
                }),
                "no 443 drop for {ip} proto {proto} in {rules:#?}"
            );
        }
    }
    for proto in [6u8, 17u8] {
        assert!(
            rules.iter().any(|r| {
                r.verdict == NftVerdict::Drop
                    && r.matches.contains(&NftMatch::Protocol(proto))
                    && r.matches.contains(&NftMatch::DstPort(853))
                    && !r
                        .matches
                        .iter()
                        .any(|m| matches!(m, NftMatch::DstV4 { .. }))
            }),
            "the DoT cut must be global, not per-resolver: {rules:#?}"
        );
    }
}

// ── DoH/DoT lockdown EQUIVALENCE (Windows only) ─────────────────────────────
// `plan_doh_dot_block` → `lower_windows::lower_doh_dot_block` must produce the
// SAME per-resolver 443 blocks + global 853 blocks as
// `killswitch_codegen::doh_dot_block_filters`.
#[cfg(windows)]
#[test]
fn slice_doh_dot_matches_current_codegen() {
    use crate::killswitch_codegen::doh_dot_block_filters;
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let ips = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(77, 88, 8, 8)];

    let check = |block_dot: bool, expected_len: usize| {
        let current = doh_dot_block_filters(sid, &ips, block_dot);
        assert_eq!(
            current.len(),
            expected_len,
            "codegen DoH filter count (block_dot={block_dot})"
        );
        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_doh_dot_block(sid, &ips, block_dot),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_doh_dot_block(&plan);
        assert!(
            behaviorally_equivalent(&current, &lowered),
            "neutral pipeline must install the SAME DoH/DoT blocks as the codegen \
                 (block_dot={block_dot})"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "DoH/DoT block arbitration order must be preserved (block_dot={block_dot})"
        );
    };

    // Per packed chunk: TCP+UDP on 443; + global DoT (TCP+UDP on 853).
    let chunks = nrr_platform_api::wfp_slotting::pack_v4(ips).len();
    check(true, chunks * 2 + 2);
    // Without DoT: only the packed 443 blocks.
    check(false, chunks * 2);
}

// A loopback / link-local resolver IP is never blocked (safety valve).
#[test]
fn doh_lockdown_skips_exempt_resolver_ips() {
    use crate::killswitch_codegen::doh_dot_block_filters;
    let sid = "S-1-5-21-1-2-3-1001";
    let ips = [
        Ipv4Addr::new(127, 0, 0, 1),   // loopback — skipped
        Ipv4Addr::new(169, 254, 1, 1), // link-local — skipped
        Ipv4Addr::new(9, 9, 9, 9),     // public — blocked
    ];
    let filters = doh_dot_block_filters(sid, &ips, false);
    assert_eq!(filters.len(), 2, "only the public IP yields TCP+UDP blocks");
    assert!(filters
        .iter()
        .all(|f| f.covers_v4(Ipv4Addr::new(9, 9, 9, 9))));
    assert!(!filters
        .iter()
        .any(|f| f.covers_v4(Ipv4Addr::new(127, 0, 0, 1))
            || f.covers_v4(Ipv4Addr::new(169, 254, 1, 1))));
}

// ── EQUIVALENCE — multi-protocol kill-switch (Windows only) ─────────────────
// `plan_kill_switch_destinations` → `lower_windows::lower_kill_switch` must
// reproduce `killswitch_codegen::kill_switch_filters` for the FULL protocol
// surface, not just TCP/UDP: the ALL default (proto-agnostic ALE + packet
// pairs), an ICMP-only selection (`other == false`, one named packet pair, no
// ALE), and an all-except-ICMP selection (`other == true`, block-all + an ICMP
// permit exception). Two destinations exercise the per-destination `idx * 16`
// packet slot window.
#[cfg(windows)]
#[test]
fn slice4b_multiprotocol_kill_switch_matches_current_codegen() {
    use crate::killswitch_codegen::{kill_switch_filters, KillSwitchProtocols};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let luid = 0x1234_5678_u64;
    let ips = [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
    ];

    // A helper: lower the neutral plan for `protos` and compare to the codegen.
    let check = |protos: KillSwitchProtocols, expected_len: usize| {
        let current = kill_switch_filters(sid, &ips, luid, protos);
        assert_eq!(
            current.len(),
            expected_len,
            "codegen filter count for {protos:?}"
        );
        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_kill_switch_destinations(sid, &ips, protos),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_kill_switch(&plan, luid);
        assert!(
            behaviorally_equivalent(&current, &lowered),
            "neutral pipeline must install the SAME kill-switch filters as the \
                 codegen for {protos:?}"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "arbitration order must be preserved for {protos:?}"
        );
    };

    // ALL (the 127 default): per dest, ALE pair (proto-agnostic) + one packet
    // pair per NAMED protocol (ICMP/IGMP/GRE/ESP, no agnostic
    // pair) = 2 + 8 = 10; two dests = 20.
    check(KillSwitchProtocols::ALL, 20);

    // ICMP only: no ALE pair, one packet egress pair per dest = 2; two = 4.
    check(
        KillSwitchProtocols {
            tcp: false,
            udp: false,
            icmp: true,
            igmp: false,
            gre: false,
            esp: false,
            other: false,
        },
        4,
    );

    // All-except-ICMP: ALE pair (tcp/udp) + one packet pair per remaining
    // named protocol (IGMP/GRE/ESP — unchecked ICMP simply gets
    // no filter) = 2 + 6 = 8 per dest; two = 16.
    check(
        KillSwitchProtocols {
            icmp: false,
            ..KillSwitchProtocols::ALL
        },
        16,
    );
}

// ── EQUIVALENCE — catch-all (Mode-B) kill-switch (Windows only) ─────────────
// `plan_catch_all_kill_switch` → `lower_windows::lower_catch_all_kill_switch`
// must reproduce `killswitch_codegen::catch_all_kill_switch_filters` — the
// blanket block-everything-not-exempted with its loopback/link-local/broadcast/
// server/LAN exemptions, the ALE + packet catch-all blocks, and the IPv6 cut —
// across the ALL default, a TCP/UDP-only mask (no V4 packet layer), and an
// all-except-ICMP mask (block-all + an ICMP permit exception).
#[cfg(windows)]
#[test]
fn slice4c_catch_all_kill_switch_matches_current_codegen() {
    use crate::killswitch_codegen::{
        catch_all_kill_switch_filters, KillSwitchProtocols, KillSwitchResolution,
    };
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let luid = 0x0001_0000_0000_0007_u64;
    let servers = [Ipv4Addr::new(203, 0, 113, 7)];
    let local_subnets = [(Ipv4Addr::new(192, 168, 1, 0), 24)];
    let resolution = KillSwitchResolution {
        secondary_luid: luid,
        bootstrap_server_ips: servers.to_vec(),
        bootstrap_server_ips_v6: Vec::new(),
        local_subnets: local_subnets.to_vec(),
        local_subnets_v6: Vec::new(),
        foreign_tunnel_luids: Vec::new(),
    };

    let check = |protos: KillSwitchProtocols, expected_len: usize| {
        let current = catch_all_kill_switch_filters(
            sid,
            &resolution,
            &crate::killswitch_codegen::FailClosedExemptions::default(),
            protos,
        );
        assert_eq!(
            current.len(),
            expected_len,
            "codegen catch-all filter count for {protos:?}"
        );
        let plan = EnforcementPlan {
            principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
                .expect("valid sid"),
            flows: plan_catch_all_kill_switch(
                sid,
                &servers,
                &local_subnets,
                Ipv6Exemptions::default(),
                protos,
            ),
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let lowered = nrr_platform_windows::lower_windows::lower_catch_all_kill_switch(&plan, luid);
        assert!(
            behaviorally_equivalent(&current, &lowered),
            "neutral pipeline must install the SAME catch-all filters as the \
                 codegen for {protos:?}"
        );
        assert!(
            arbitration_order_preserved(&current, &lowered),
            "catch-all arbitration order must be preserved for {protos:?}"
        );
    };

    // ALL: ALE 8 (egress+loopback+link-local+broadcast+local-network-
    // control+server+subnet+block) + packet 11 (7 mirror exempts + 4 named
    // blocks — no agnostic block-all) + IPv6 8 (4 ALE + 4 packet) = 27.
    check(KillSwitchProtocols::ALL, 27);

    // TCP/UDP only: no V4 packet layer at all → ALE 8 + IPv6 8 = 16.
    check(KillSwitchProtocols::from_bits(0x03), 16);

    // All-except-ICMP: ALE 8 + packet 10 (7 mirror exempts + IGMP/GRE/ESP
    // named blocks; unchecked ICMP simply gets no filter) + IPv6 8 = 26.
    check(
        KillSwitchProtocols {
            icmp: false,
            ..KillSwitchProtocols::ALL
        },
        26,
    );
}

// ── EQUIVALENCE — fail-closed + app kill-switch + app exempt (Windows only) ─
// The neutral pipeline must reproduce `killswitch_codegen`'s
// `app_kill_switch_filters` / `primary_app_exempt_filters` /
// `fail_closed_block_destinations` / `fail_closed_block_apps` /
// `fail_closed_block_all_filters` across the ALL / TCP-UDP-only / all-except-ICMP
// masks (and DNS-over-primary on/off for the block-all).
#[cfg(windows)]
#[test]
fn slice4d_fail_closed_and_app_kill_switch_match_current_codegen() {
    use crate::killswitch_codegen::{
        app_kill_switch_filters, fail_closed_block_all_filters, fail_closed_block_apps,
        fail_closed_block_destinations, primary_app_exempt_filters, FailClosedExemptions,
        KillSwitchProtocols,
    };
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::types::WfpFilterSpec;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};
    use nrr_platform_windows::lower_windows::{lower_catch_all_kill_switch, lower_kill_switch};

    let sid = "S-1-5-21-1-2-3-1001";
    let luid = 0x0001_0000_0000_0007_u64;
    let apps = vec![r"C:\Games\game.exe".to_string(), "*vpn*".to_string()];
    // Both families: the oracle has to see the v6 half of the pin set, or
    // it only ever proves the two pipelines agree about IPv4.
    let ips = [
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5)),
    ];
    let servers = [Ipv4Addr::new(203, 0, 113, 7)];
    let subnets = [(Ipv4Addr::new(192, 168, 1, 0), 24)];

    let plan = |flows: Vec<FlowRule>| EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
            .expect("valid sid"),
        flows,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let assert_equiv = |current: &[WfpFilterSpec], lowered: &[WfpFilterSpec], label: &str| {
        assert!(
            !current.is_empty(),
            "{label}: codegen produced no filters (test would be vacuous)"
        );
        assert!(
            behaviorally_equivalent(current, lowered),
            "{label}: neutral pipeline must install the SAME filters as the codegen"
        );
        assert!(
            arbitration_order_preserved(current, lowered),
            "{label}: arbitration order must be preserved"
        );
    };

    // (A) per-app kill-switch — ALE pair per app. Main-named addresses no
    // longer earn rescue permits: the block sits below the primary rule
    // band, so the primary rules' own permits carry them.
    let cur = app_kill_switch_filters(sid, &apps, luid, KillSwitchProtocols::ALL);
    assert_eq!(cur.len(), 4, "2 apps × (permit + block)");
    let low = lower_kill_switch(
        &plan(plan_app_kill_switch(sid, &apps, KillSwitchProtocols::ALL)),
        luid,
    );
    assert_equiv(&cur, &low, "app-kill-switch");

    // (B) primary-app exemption — one unconditional ALE permit per app.
    let cur = primary_app_exempt_filters(sid, &apps);
    assert_eq!(cur.len(), 2, "one exempt permit per app, no block");
    let low = lower_catch_all_kill_switch(&plan(plan_primary_app_exempt(sid, &apps)), luid);
    assert_equiv(&cur, &low, "primary-app-exempt");

    // (D) fail-closed per-app blocks.
    let cur = fail_closed_block_apps(sid, &apps, KillSwitchProtocols::ALL);
    assert_eq!(cur.len(), 2, "one block per app");
    let low = lower_kill_switch(
        &plan(plan_fail_closed_apps(sid, &apps, KillSwitchProtocols::ALL)),
        luid,
    );
    assert_equiv(&cur, &low, "fail-closed-apps");

    // (C) fail-closed per-destination blocks + (E) fail-closed block-all,
    // across several protocol masks and DNS-over-primary.
    let masks = [
        KillSwitchProtocols::ALL,
        KillSwitchProtocols::from_bits(0x03),
        KillSwitchProtocols {
            icmp: false,
            ..KillSwitchProtocols::ALL
        },
    ];
    for protos in masks {
        let cur = fail_closed_block_destinations(sid, &ips, protos);
        let low = lower_kill_switch(
            &plan(plan_fail_closed_destinations(sid, &ips, protos)),
            luid,
        );
        assert_equiv(&cur, &low, "fail-closed-destinations");

        let primaries = [
            Ipv4Addr::new(203, 0, 113, 50),
            Ipv4Addr::new(203, 0, 113, 51),
        ];
        // Known-direct exemptions ride the same parity check.
        let directs = [Ipv4Addr::new(203, 0, 113, 68)];
        // The liveness-probe target (tunnel next-hop) rides the
        // same parity check as every other exemption.
        let probes = [Ipv4Addr::new(10, 91, 192, 1)];
        for allow_dns in [false, true] {
            let ex = FailClosedExemptions {
                bootstrap_server_ips: servers.to_vec(),
                bootstrap_server_ips_v6: Vec::new(),
                local_subnets: subnets.to_vec(),
                local_subnets_v6: Vec::new(),
                foreign_tunnel_luids: Vec::new(),
                primary_dest_ips: primaries.to_vec(),
                allow_dns_over_primary: allow_dns,
                known_direct_ips: directs.to_vec(),
                probe_target_ips: probes.to_vec(),
                secondary_luid: 0,
            };
            let cur = fail_closed_block_all_filters(sid, &ex, protos);
            let low = lower_catch_all_kill_switch(
                &plan(plan_fail_closed_block_all(
                    sid,
                    &servers,
                    &probes,
                    &subnets,
                    &primaries,
                    &directs,
                    Ipv6Exemptions::default(),
                    allow_dns,
                    protos,
                )),
                luid,
            );
            assert_equiv(&cur, &low, "fail-closed-block-all");
        }
    }
}

// ── EQUIVALENCE — fail-closed default block (Windows only) ──────────────────
// With `StrictSecondaryFailClosed`, `plan_route_rules` → `lower_route_rules`
// must reproduce the whole `generate_filters` output INCLUDING the trailing
// `default_block_spec` catch-all block (`wfp_codegen`).
#[cfg(windows)]
#[test]
fn slice5_fail_closed_default_block_matches_current_codegen() {
    use crate::wfp_codegen::{generate_filters, CodegenInput};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::types::WfpAction;
    use nrr_platform_api::wfp_behavioral::{arbitration_order_preserved, behaviorally_equivalent};

    let sid = "S-1-5-21-1-2-3-1001";
    let rb = book(
        vec![exact_ip_rule("p-ip", Ipv4Addr::new(192, 0, 2, 5))],
        vec![rule(
            "s-block",
            CanonicalAddressMatch::ExactIp(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
            RuleAction::Block,
        )],
    );
    let cache = MapCache::default();
    let resolver = MapResolver::default();
    let obs = MapObs::default();
    let denylist = std::collections::HashSet::new();
    let current = generate_filters(CodegenInput {
        sid,
        rule_book: &rb,
        behavior_mode: RouteBehaviorMode::StrictSecondaryFailClosed,
        fqdn_cache: &cache,
        app_observations: &obs,
        app_resolver: &resolver,
        secondary_ip_denylist: &denylist,
        zone_priority_over_ip: false,
        families: crate::enforcement_planner::FamilyScope::V4Only,
    });

    let plan = EnforcementPlan {
        principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(sid)
            .expect("valid sid"),
        flows: plan_route_rules(
            &rb,
            sid,
            RouteBehaviorMode::StrictSecondaryFailClosed,
            &planner_input(&cache, &resolver, &obs),
        )
        .0,
        routes: Vec::new(),
        policy_rules: Vec::new(),
    };
    let lowered = nrr_platform_windows::lower_windows::lower_route_rules(&plan);

    // 1 ExactIp permit + Block (ALE + packet mirror) + default block = 4.
    assert_eq!(current.filters.len(), 4, "sanity: incl the default block");
    assert_eq!(
        current
            .filters
            .iter()
            // Unconditional means NO destination at all — a packed
            // filter carries its addresses in `remote_ip_set`, so checking
            // the single field alone would count one as unconditional.
            .filter(|f| f.action == WfpAction::Block
                && f.remote_ip.is_none()
                && f.remote_ip_set.is_empty()
                && f.remote_subnet.is_none())
            .count(),
        1,
        "exactly one unconditional default block in the codegen output"
    );
    assert!(
        behaviorally_equivalent(&current.filters, &lowered),
        "neutral pipeline must install the default block too"
    );
    assert!(arbitration_order_preserved(&current.filters, &lowered));
}

// ── EQUIVALENCE — system route table (Windows only) ──────────────────────────
// `plan_routes` → `lower_windows::lower_routes` must produce the SAME route SET
// as `route_codegen::generate_routes` across both behavior modes, with/without a
// primary target, and through the shared-IP denylist — covering the /32 host
// fan-out (ExactIp / ExactFqdn / Suffix), dedup, non-routable skip, the /1 and
// /2 overlays, and the primary exceptions.
#[cfg(windows)]
#[test]
fn slice5_routes_match_current_codegen() {
    use crate::route_codegen::{generate_routes, SecondaryRouteTarget};
    use nrr_platform_api::enforcement::EnforcementPlan;
    use nrr_platform_api::RouteEntry;
    use nrr_platform_windows::lower_windows::{lower_routes, RouteTarget};

    fn route_sets_equal(a: &[RouteEntry], b: &[RouteEntry]) -> bool {
        a.len() == b.len() && a.iter().all(|r| b.contains(r)) && b.iter().all(|r| a.contains(r))
    }

    let mut cache = MapCache::default();
    cache.hosts.insert(
        "api.example.com".into(),
        vec![v4(203, 0, 113, 1), v4(203, 0, 113, 2)],
    );
    cache.suffixes.insert(
        "corp.example".into(),
        vec!["a.corp.example".into(), "b.corp.example".into()],
    );
    cache
        .hosts
        .insert("a.corp.example".into(), vec![v4(198, 51, 100, 1)]);
    cache
        .hosts
        .insert("b.corp.example".into(), vec![v4(198, 51, 100, 2)]);

    // Secondary: an ExactIp, a duplicate of it (dedup), a Suffix fan-out, a
    // loopback (non-routable skip). Primary: an ExactIp + an ExactFqdn fan-out.
    let rb = book(
        vec![
            exact_ip_rule("p-ip", Ipv4Addr::new(8, 8, 8, 8)),
            rule(
                "p-fqdn",
                CanonicalAddressMatch::ExactFqdn("api.example.com".into()),
                RuleAction::Route,
            ),
        ],
        vec![
            exact_ip_rule("s-ip", Ipv4Addr::new(1, 1, 1, 1)),
            exact_ip_rule("s-ip-dup", Ipv4Addr::new(1, 1, 1, 1)),
            rule(
                "s-suffix",
                CanonicalAddressMatch::SuffixDomain("corp.example".into()),
                RuleAction::Route,
            ),
            exact_ip_rule("s-loop", Ipv4Addr::new(127, 0, 0, 1)),
            // An app-only rule: routed from observations on both sides, so
            // the equivalence covers the destinations the Windows codegen
            // learns rather than resolves.
            CanonicalRule {
                id: nrr_domain::RuleId("s-app".into()),
                enabled: true,
                address_match: None,
                app_match: Some(nrr_domain::canonical::CanonicalAppMatch {
                    pattern: CanonicalAppPattern::Exact("messenger.exe".into()),
                    include_child_processes: false,
                }),
                comment: String::new(),
                action: RuleAction::Route,
                origin: None,
            },
        ],
    );

    let sec = SecondaryRouteTarget {
        gateway: Ipv4Addr::new(10, 0, 0, 1),
        gateway_v6: None,
        interface_index: 7,
    };
    let pri = SecondaryRouteTarget {
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        gateway_v6: None,
        interface_index: 12,
    };
    let sec_target = RouteTarget {
        gateway: sec.gateway,
        gateway_v6: Ipv6Addr::UNSPECIFIED,
        interface_index: sec.interface_index,
    };
    let pri_target = RouteTarget {
        gateway: pri.gateway,
        gateway_v6: Ipv6Addr::UNSPECIFIED,
        interface_index: pri.interface_index,
    };

    // A shared-IP denylist that drops one secondary destination (mode A only).
    let denied: std::collections::HashSet<Ipv4Addr> =
        [Ipv4Addr::new(198, 51, 100, 2)].into_iter().collect();

    for denylist in [std::collections::HashSet::new(), denied] {
        for mode in [
            RouteBehaviorMode::PreferPrimary,
            RouteBehaviorMode::PreferSecondaryWhenAvailable,
            RouteBehaviorMode::StrictSecondaryFailClosed,
        ] {
            for has_primary in [false, true] {
                let primary_opt = has_primary.then_some(&pri);
                let apps = crate::app_observation_lookup::MockAppObservationLookup::new();
                apps.set_ips("messenger.exe", vec![Ipv4Addr::new(203, 0, 113, 7)]);
                let current = generate_routes(
                    mode,
                    &rb,
                    primary_opt,
                    &sec,
                    &cache,
                    &apps,
                    &denylist,
                    crate::address_ownership::ZoneVsIpOrder::default(),
                    &[],
                );
                let plan = EnforcementPlan {
                    principal: nrr_platform_api::enforcement::UserPrincipal::from_windows_sid(
                        "S-1-5-21-A",
                    )
                    .expect("valid sid"),
                    flows: Vec::new(),
                    routes: plan_routes(
                        mode,
                        &rb,
                        has_primary,
                        &cache,
                        &apps,
                        &denylist,
                        FamilyScope::V4Only,
                        crate::address_ownership::ZoneVsIpOrder::default(),
                    ),
                    policy_rules: Vec::new(),
                };
                let lowered = lower_routes(&plan, sec_target, has_primary.then_some(pri_target));
                assert!(
                    route_sets_equal(&current.routes, &lowered),
                    "route set mismatch for mode {mode:?}, has_primary {has_primary}\n\
                         codegen: {:#?}\nlowered: {:#?}",
                    current.routes,
                    lowered
                );
            }
        }
    }
}
