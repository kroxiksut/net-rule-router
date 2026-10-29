//! The route half of the plan: host routes, overlays and the fake-IP pool.

use super::*;
use crate::route_codegen::network_routes::{
    plan_network_routes, NetworkRouteFacts, NetworkRoutePlan,
};
use crate::route_codegen::NETWORK_ROUTE_METRIC;

// ── System route table (route_codegen) ──────────────────────────────────────────

/// Plan the **system route table** for `mode` into neutral
/// [`RouteIntent`]s — the neutral equivalent of `route_codegen::generate_routes`
/// (the routing mechanism; the WFP planners above are the blocking one).
///
/// - **`PreferPrimary`** (mode A): secondary-bound rules → `/32` via
///   [`EgressRef::Secondary`], through the denylist-filtered cache view; with a
///   primary target (`has_primary`), the counter-overlay via [`EgressRef::Primary`]
///   so non-rule traffic rides the primary. Shaped by the same
///   [`counter_overlay_for`] as the codegen: a fixed `/2` set loses to a tunnel
///   that redirects with narrower prefixes.
/// - **`PreferSecondaryWhenAvailable`** (mode B): the
///   `/1` split-default overlay ([`OVERLAY_LOW`] + [`OVERLAY_HIGH`]) via the
///   secondary, plus (with a primary target) the primary-bound rules pulled back
///   as `/32` exceptions via the primary.
///
/// `has_primary` gates the primary-egress routes (no primary bound → the codegen's
/// `PrimaryExceptionsUnavailable` path, which emits none). `denied` is the
/// shared-IP policy denylist applied to the mode-A secondary fan-out only.
/// `lower_windows::lower_routes` resolves each [`EgressRef`] to its concrete
/// gateway + interface index. Pure: no I/O beyond the injected cache reader.
// Independent inputs, none of which belongs to another: grouping them into a
// bag would hide which ones a caller actually varies.
#[allow(clippy::too_many_arguments)]
pub fn plan_routes(
    mode: RouteBehaviorMode,
    rule_book: &CanonicalRuleBook,
    has_primary: bool,
    cache: &dyn FqdnCacheLookup,
    app_observations: &dyn AppObservationLookup,
    denied: &HashSet<Ipv4Addr>,
    families: FamilyScope,
    // The principal's `zone_priority_over_ip` and `app_rules_take_all_addresses`.
    // Both reach the ownership arbiter only, so this is the whole of their reach.
    order: impl Into<crate::address_ownership::OwnershipSettings>,
    // The tunnel's own catch-all prefixes; empty when they are not known.
    tunnel_catch_alls: &[(Ipv4Addr, u8)],
) -> Vec<RouteIntent> {
    plan_routes_with(
        mode,
        rule_book,
        has_primary,
        cache,
        app_observations,
        denied,
        families,
        order,
        tunnel_catch_alls,
        &NetworkRouteFacts::from_catch_alls(tunnel_catch_alls),
        crate::wfp_codegen::current_rule_shape_support(),
    )
}

/// [`plan_routes`] with what the machine says about its links, which network
/// rules are routed around, and the shape support to plan under — the neutral
/// twin of `route_codegen::generate_routes_with`, lowering the same
/// [`plan_network_routes`].
#[allow(clippy::too_many_arguments)]
pub fn plan_routes_with(
    mode: RouteBehaviorMode,
    rule_book: &CanonicalRuleBook,
    has_primary: bool,
    cache: &dyn FqdnCacheLookup,
    app_observations: &dyn AppObservationLookup,
    denied: &HashSet<Ipv4Addr>,
    families: FamilyScope,
    order: impl Into<crate::address_ownership::OwnershipSettings>,
    tunnel_catch_alls: &[(Ipv4Addr, u8)],
    networks: &NetworkRouteFacts,
    support: nrr_domain::rule_shape::RuleShapeSupport,
) -> Vec<RouteIntent> {
    let mut routes = Vec::new();
    // Ownership from the UNFILTERED cache: the denylist view exists to trim
    // what goes to the tunnel, and reading it here would understate what the
    // main link claims.
    let ownership = crate::address_ownership::AddressOwnership::resolve_for(
        rule_book,
        cache,
        order.into(),
        support,
        app_observations,
    );
    match mode {
        RouteBehaviorMode::PreferPrimary => {
            // Secondary rules → /32 via the secondary, minus any declined shared IP.
            let secondary_cache = DenylistFilteredCache::new(cache, denied);
            let mut seen = BTreeSet::new();
            plan_host_routes(
                &rule_book.secondary,
                EgressRef::Secondary,
                &secondary_cache,
                &crate::address_ownership::AppDestinationGate::for_rule_set(
                    &ownership,
                    app_observations,
                    &rule_book.secondary,
                )
                .with_declined(denied),
                &ownership,
                families,
                &mut seen,
                &mut routes,
            );
            // Mode-A counter-overlay via the primary (needs a primary).
            if has_primary {
                for (net, prefix) in counter_overlay_for(tunnel_catch_alls) {
                    routes.push(overlay_intent(net, prefix, EgressRef::Primary));
                }
            }
        }
        RouteBehaviorMode::PreferSecondaryWhenAvailable => {
            // Own the split-default overlay → all traffic to the tunnel.
            routes.push(overlay_intent(
                OVERLAY_LOW.0,
                OVERLAY_LOW.1,
                EgressRef::Secondary,
            ));
            routes.push(overlay_intent(
                OVERLAY_HIGH.0,
                OVERLAY_HIGH.1,
                EgressRef::Secondary,
            ));
            // Carve primary-bound rules back onto the primary as /32 exceptions.
            if has_primary {
                let mut seen = BTreeSet::new();
                plan_host_routes(
                    &rule_book.primary,
                    EgressRef::Primary,
                    cache,
                    &crate::address_ownership::AppDestinationGate::for_rule_set(
                        &ownership,
                        app_observations,
                        &rule_book.primary,
                    ),
                    &ownership,
                    families,
                    &mut seen,
                    &mut routes,
                );
            }
        }
    }
    let plan = plan_network_routes(
        mode,
        rule_book,
        has_primary,
        &ownership,
        networks,
        tunnel_catch_alls,
        support,
    );
    push_network_intents(plan, families, &mut routes);
    // A host on an attached segment is reached directly; a name resolving to
    // it does not pull it into the tunnel — the gate the Windows codegen
    // applies too (`NetworkRouteFacts::keeps_host_direct`).
    routes.retain(|r| {
        let host = match r.dst {
            DstMatch::HostV4(ip) => Some(IpAddr::V4(ip)),
            DstMatch::HostV6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        };
        !(r.egress == EgressRef::Secondary
            && host.is_some_and(|ip| networks.keeps_host_direct(&rule_book.secondary, ip)))
    });
    routes
}

/// Lower a network plan into intents, after the host routes — the order and
/// the dedup `route_codegen::push_network_plan` uses.
fn push_network_intents(plan: NetworkRoutePlan, families: FamilyScope, out: &mut Vec<RouteIntent>) {
    let egress_of = |link| match link {
        crate::address_ownership::Link::Main => EgressRef::Primary,
        crate::address_ownership::Link::Additional => EgressRef::Secondary,
    };
    let mut hosts: HashSet<(IpAddr, bool)> = out
        .iter()
        .filter_map(|r| match r.dst {
            DstMatch::HostV4(ip) => Some((IpAddr::V4(ip), r.egress == EgressRef::Primary)),
            DstMatch::HostV6(ip) => Some((IpAddr::V6(ip), r.egress == EgressRef::Primary)),
            _ => None,
        })
        .collect();
    for (link, ip) in plan.hosts {
        let egress = egress_of(link);
        if !families.admits(ip)
            || crate::net_filter::is_non_routable(&ip)
            || !hosts.insert((ip, egress == EgressRef::Primary))
        {
            continue;
        }
        out.push(RouteIntent {
            dst: host_match(ip),
            egress,
            metric: SECONDARY_ROUTE_METRIC,
            table: RouteTableRef::Main,
        });
    }
    for (link, block) in plan.networks {
        let egress = egress_of(link);
        if !families.admits(block.network())
            || (block.is_single_address()
                && hosts.contains(&(block.network(), egress == EgressRef::Primary)))
        {
            continue;
        }
        out.push(RouteIntent {
            dst: subnet_match(block),
            egress,
            metric: NETWORK_ROUTE_METRIC,
            table: RouteTableRef::Main,
        });
    }
}

/// Plan the `/32` host routes for one ruleset (neutral equivalent of
/// `route_codegen::generate_secondary_routes`), deduped by destination across
/// rules via `seen`. Skips disabled / `Block` rules and non-routable
/// destinations, capped per rule at [`MAX_ROUTES_PER_RULE`].
///
/// An APPLICATION-only rule routes the destinations the app has been observed
/// using, exactly as the Windows codegen does: the app's permit is conditional
/// on the traffic leaving that link, so without the route the packet leaves the
/// other one, misses its own permit and is dropped.
#[allow(clippy::too_many_arguments)]
fn plan_host_routes(
    rules: &CanonicalRuleSet,
    egress: EgressRef,
    cache: &dyn FqdnCacheLookup,
    gate: &crate::address_ownership::AppDestinationGate<'_>,
    ownership: &crate::address_ownership::AddressOwnership,
    families: FamilyScope,
    seen: &mut BTreeSet<IpAddr>,
    out: &mut Vec<RouteIntent>,
) {
    let link = match egress {
        EgressRef::Primary => crate::address_ownership::Link::Main,
        _ => crate::address_ownership::Link::Additional,
    };
    for rule in rules.rules() {
        if !rule.enabled || matches!(rule.action, RuleAction::Block) {
            continue;
        }
        // A rule carrying BOTH conditions matches as AND, and no route table
        // scopes a route to a process — routing its address would ignore the
        // application half and move every other process too.
        if rule.app_match.is_some() && rule.address_match.is_some() {
            continue;
        }
        let mut per_rule = 0usize;
        if let Some(app) = rule.app_match.as_ref() {
            // A rule by path is observed under its canonical spelling.
            let pattern = match &app.pattern {
                CanonicalAppPattern::Exact(s) | CanonicalAppPattern::Glob(s) => s.as_str(),
                CanonicalAppPattern::Path(path) => path.as_str(),
            };
            for ip in gate.admit(pattern, link).admitted {
                if !push_host_route(IpAddr::V4(ip), &egress, seen, out, &mut per_rule) {
                    break;
                }
            }
            continue;
        }
        // The same gate the Windows route codegen applies: an address the main
        // link's rules also name stays on the main link.
        let steerable = |ip: IpAddr| ownership.address_rule_may_steer(ip, link);
        match &rule.address_match {
            Some(CanonicalAddressMatch::ExactIp(ip)) => {
                if families.admits(*ip) && steerable(*ip) {
                    push_host_route(*ip, &egress, seen, out, &mut per_rule);
                }
            }
            // Routed by `plan_network_routes`, which needs both links' networks.
            Some(CanonicalAddressMatch::Subnet(_) | CanonicalAddressMatch::IpRange(_)) => {}
            // Carried by its `*.site.<zone>` twins (`any_zone_sites`).
            Some(CanonicalAddressMatch::AnyZoneDomain(_)) => {}
            Some(CanonicalAddressMatch::ExactFqdn(host)) => {
                for ip in capped_for_host(cache, host, families) {
                    if !steerable(ip) {
                        continue;
                    }
                    if !push_host_route(ip, &egress, seen, out, &mut per_rule) {
                        break;
                    }
                }
            }
            Some(CanonicalAddressMatch::SuffixDomain(_)) | Some(CanonicalAddressMatch::Zone(_)) => {
                // `*.suffix` covers its apex, a zone does not — the same split
                // `route_codegen::fanout_suffix` makes, so the neutral plan and
                // the Windows route codegen produce the same destinations.
                let hosts = match &rule.address_match {
                    Some(CanonicalAddressMatch::SuffixDomain(suffix)) => {
                        cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
                    }
                    Some(CanonicalAddressMatch::Zone(zone)) => {
                        cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP)
                    }
                    _ => Vec::new(),
                };
                'outer: for sub in hosts {
                    for ip in capped_for_host(cache, &sub, families) {
                        if !steerable(ip) {
                            continue;
                        }
                        if !push_host_route(ip, &egress, seen, out, &mut per_rule) {
                            break 'outer;
                        }
                    }
                }
            }
            None => {}
        }
    }
}

/// Append a `/32` route intent for `ip` (deduped, per-rule capped), mirroring
/// `route_codegen::push_route`. Returns `false` only on a per-rule cap hit so the
/// caller stops fanning out; a non-routable or already-seen IP returns `true`
/// (skip, keep scanning).
fn push_host_route(
    ip: IpAddr,
    egress: &EgressRef,
    seen: &mut BTreeSet<IpAddr>,
    out: &mut Vec<RouteIntent>,
    per_rule: &mut usize,
) -> bool {
    if *per_rule >= MAX_ROUTES_PER_RULE {
        return false;
    }
    // Never route a non-routable destination (an ad-block hosts file pins a domain
    // to loopback/unspecified); loopback never leaves the box.
    if crate::net_filter::is_non_routable(&ip) {
        return true;
    }
    if !seen.insert(ip) {
        return true;
    }
    out.push(RouteIntent {
        dst: host_match(ip),
        egress: egress.clone(),
        metric: SECONDARY_ROUTE_METRIC,
        table: RouteTableRef::Main,
    });
    *per_rule += 1;
    true
}

/// While the tunnel carries the default, its own transport must not: a kernel
/// tunnel's packets are routed as root, meet the `/1` halves and loop into the
/// tunnel (WireGuard drops them with `ELOOP` and is dead after the next rekey).
/// Each known server gets a host route via the main link, in place of one a
/// rule planned into the tunnel.
pub fn pin_tunnel_servers_to_primary(
    servers: &[IpAddr],
    families: FamilyScope,
    routes: &mut Vec<RouteIntent>,
) {
    let carries_default = routes.iter().any(|r| {
        r.egress == EgressRef::Secondary && matches!(r.dst, DstMatch::SubnetV4 { prefix: 1, .. })
    });
    if !carries_default {
        return;
    }
    for &ip in servers {
        if !families.admits(ip) || crate::net_filter::is_non_routable(&ip) {
            continue;
        }
        routes.retain(|r| !(r.dst == host_match(ip) && r.egress == EgressRef::Secondary));
        if routes.iter().any(|r| r.dst == host_match(ip)) {
            continue;
        }
        routes.push(RouteIntent {
            dst: host_match(ip),
            egress: EgressRef::Primary,
            metric: SECONDARY_ROUTE_METRIC,
            table: RouteTableRef::Main,
        });
    }
}

/// One overlay route intent (a `/1` split-default half or a counter-overlay
/// block) via `egress`.
fn overlay_intent(net: Ipv4Addr, prefix: u8, egress: EgressRef) -> RouteIntent {
    RouteIntent {
        dst: DstMatch::SubnetV4 { net, prefix },
        egress,
        metric: SECONDARY_ROUTE_METRIC,
        table: RouteTableRef::Main,
    }
}

/// The fake-IP relay's pool, as neutral flows.
///
/// Two things have to be true at once for a fake-routed host to work: an
/// application must be able to open a connection to the virtual address under
/// ANY posture (including a blanket block), and — while the UDP path is off —
/// QUIC must die at connect time rather than handshake against a stack that
/// will drop its datagrams. Hence a permit for the pool and, conditionally, a
/// UDP veto above it. Both sit in [`PrecedenceClass::FakeIpPool`]: the pool is
/// machinery a rule is served THROUGH, not a destination anyone named.
///
/// `ordinal` order is the emission order of the shipped codegen (v4 permit, v6
/// permit, v4 UDP veto, v6 UDP veto), so the veto outranks the permit it
/// qualifies.
pub fn plan_fake_ip_pool(
    sid: &str,
    pool: &nrr_platform_api::fake_ip::FakeIpPoolConfig,
    udp_relay_enabled: bool,
) -> Vec<FlowRule> {
    let principal = principal_scope(sid);
    let mut flows = Vec::new();
    let mut push = |ordinal: u32, verdict: Verdict, dst: DstMatch, protocol: Option<L4Proto>| {
        flows.push(FlowRule {
            verdict,
            precedence: Precedence {
                class: PrecedenceClass::FakeIpPool,
                ordinal,
            },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol,
            },
            principal: principal.clone(),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
            observed_by_program: false,
        })
    };

    push(
        0,
        Verdict::Permit,
        DstMatch::SubnetV4 {
            net: pool.v4_base,
            prefix: pool.v4_prefix_len,
        },
        None,
    );
    if let Some(v6) = pool.v6_base {
        push(
            1,
            Verdict::Permit,
            DstMatch::SubnetV6 {
                net: v6,
                prefix: pool.v6_prefix_len,
            },
            None,
        );
    }
    if !udp_relay_enabled {
        push(
            2,
            Verdict::Block,
            DstMatch::SubnetV4 {
                net: pool.v4_base,
                prefix: pool.v4_prefix_len,
            },
            Some(L4Proto::Udp),
        );
        if let Some(v6) = pool.v6_base {
            push(
                3,
                Verdict::Block,
                DstMatch::SubnetV6 {
                    net: v6,
                    prefix: pool.v6_prefix_len,
                },
                Some(L4Proto::Udp),
            );
        }
    }
    flows
}

/// Name what an address rule failed to resolve to, so the caller can say which
/// rule is waiting on DNS rather than reporting silence.
///
/// An `ExactIp` always resolves; the rest depend on the cache being warm. The
/// backstop is reported separately: a fan-out that STOPPED is a different fact
/// from one that found nothing.
pub(super) fn note_address_resolution(
    report: &mut PlanReport,
    rule: &CanonicalRule,
    addr_match: &CanonicalAddressMatch,
    resolved_any: bool,
    cache: &dyn FqdnCacheLookup,
) {
    let name = match addr_match {
        CanonicalAddressMatch::ExactIp(_)
        | CanonicalAddressMatch::Subnet(_)
        | CanonicalAddressMatch::IpRange(_)
        | CanonicalAddressMatch::AnyZoneDomain(_) => return,
        CanonicalAddressMatch::ExactFqdn(host) => host,
        CanonicalAddressMatch::SuffixDomain(suffix) => suffix,
        CanonicalAddressMatch::Zone(zone) => zone,
    };
    if !resolved_any {
        report.unresolved_hosts.push(name.clone());
        return;
    }
    let subdomains = match addr_match {
        CanonicalAddressMatch::SuffixDomain(suffix) => {
            cache.hostnames_for_suffix_domain(suffix, SUFFIX_FANOUT_BACKSTOP)
        }
        CanonicalAddressMatch::Zone(zone) => {
            cache.hostnames_under_suffix(zone, SUFFIX_FANOUT_BACKSTOP)
        }
        _ => return,
    };
    if subdomains.len() >= SUFFIX_FANOUT_BACKSTOP {
        report.truncated_suffixes.push((
            rule.id.as_str().to_string(),
            name.clone(),
            SUFFIX_FANOUT_BACKSTOP,
        ));
    }
}

/// What planning could NOT do, in the words the GUI shows the user.
///
/// A rule that resolves to nothing emits no flow, and a plan cannot say why:
/// the absence looks identical to "the user has no such rule". The shipped
/// codegen answered this with a diagnostics stream; the neutral planner answers
/// it with this report, returned alongside the flows so a caller cannot take
/// the plan and quietly drop the reasons.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlanReport {
    /// Application rules whose name/glob resolved to no executable on disk.
    pub unresolved_apps: Vec<String>,
    /// Hostnames, suffixes and zones with nothing cached under them.
    pub unresolved_hosts: Vec<String>,
    /// Application rules that resolved to more executables than the fan-out
    /// allows: `(app, cap, resolved)`.
    pub over_capped_apps: Vec<(String, usize, usize)>,
    /// Destinations an application rule observed but did not take over, because
    /// the main link's own rules name them: `(app, address)`.
    pub claimed_by_main: Vec<(String, Ipv4Addr)>,
    /// Application rules whose program is found but whose every observed
    /// address went elsewhere, so they carry none of its traffic.
    pub unrouted_apps: Vec<(String, crate::address_ownership::AppTrafficElsewhere)>,
    /// Suffix/zone fan-outs stopped at the backstop: `(rule_id, suffix, cap)`.
    pub truncated_suffixes: Vec<(String, String, usize)>,
    /// Where the user's rules contradict each other, unsupported shapes
    /// included, in rule order — what the Overlaps screen lists.
    pub conflicts: Vec<crate::rule_conflicts::RuleConflict>,
    /// Destinations of the additional link's application rules that the
    /// program's own permit/block pair already guards: observed for a program
    /// that resolved, and not taught by a script an interpreter elsewhere ran.
    /// The kill switch pins none of them per destination.
    pub app_guarded_additional: Vec<Ipv4Addr>,
    /// `(app, address)` an application rule left alone because other programs
    /// use the address too.
    pub used_by_others: Vec<(String, Ipv4Addr)>,
    /// `(folder, covered)` for rules by folder that hold more programs than
    /// the fan-out takes.
    pub over_capped_folders: Vec<(String, usize)>,
}

impl PlanReport {
    /// Rules skipped because their shape cannot be enforced as written.
    #[must_use]
    pub fn unsupported_shapes(
        &self,
    ) -> Vec<(String, nrr_domain::rule_shape::UnsupportedShapeReason)> {
        self.conflicts
            .iter()
            .filter_map(|c| match c {
                crate::rule_conflicts::RuleConflict::UnsupportedRuleShape { rule_id, reason } => {
                    Some((rule_id.clone(), *reason))
                }
                _ => None,
            })
            .collect()
    }
}
