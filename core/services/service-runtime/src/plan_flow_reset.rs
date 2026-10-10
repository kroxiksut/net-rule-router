//! Tearing down the connections an applied plan change left on their old path,
//! for platforms whose apply is one whole-plan pass ([`PrincipalEnforcementCycle`]).
//!
//! A socket keeps the path it was opened on: the page the user just added a
//! rule for goes on loading over the old link until something breaks it. The
//! trigger here is the plan itself — a host destination, or a network a rule
//! pins, whose steering differs from the steering last made visible to
//! connections, or, when the additional link has just become usable, every
//! destination steered onto it (its addresses did not change while it was
//! down, so the diff alone finds nothing). Who may be cut is
//! [`flows_to_reset`]'s decision, the same one the per-SID activation path
//! makes: the plan's owner only, nothing to an address the shared-IP census has
//! seen serving a direct host.
//!
//! Only networks a rule pins count: the plan also carries exemptions and route
//! overlays as networks (loopback, the LAN, the split-default halves), and
//! tearing those down would cut connections no rule changed.
//!
//! Of those connections, one riding a link that is neither of the principal's
//! is spared, and so is one already on the link its destination is steered
//! onto: no route of ours moves either.
//!
//! A destination that LEFT the plan is torn down only if it was steered onto the
//! additional link: its route is gone, yet the socket keeps the tunnel's source
//! address and hangs until a timeout. One that left the main link keeps its
//! interface and goes on working, so it is left alone.
//!
//! [`PrincipalEnforcementCycle`]: crate::principal_enforcement::PrincipalEnforcementCycle
//! [`flows_to_reset`]: crate::routed_host_flow_refresh::flows_to_reset

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use nrr_platform_api::enforcement::{
    DstMatch, EgressConstraint, EgressRef, EnforcementPlan, L4Proto, PrecedenceClass,
    RouteTableRef, UserPrincipal, Verdict,
};
use nrr_platform_api::fake_ip::stale_flows::{FlowLinks, FlowTargets, StaleFlowReset};
use nrr_shared::ip_block::IpBlock;
use nrr_shared::RouteRole;

use crate::flow_reset_log::{log_reset_flows, ResetCause};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::routed_host_flow_refresh::{reset_owner_flows, Course, Courses, FlowPaths};

/// How a plan treats one destination — what a connection to it would notice
/// changing. Ordinals and application scope are left out: renumbering a rule
/// or re-resolving a program's path moves no traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Steer {
    Flow {
        verdict: Verdict,
        class: PrecedenceClass,
        egress: EgressConstraint,
        port: Option<u16>,
        protocol: Option<L4Proto>,
    },
    Route {
        egress: EgressRef,
        table: RouteTableRef,
    },
}

impl Steer {
    fn onto_secondary(&self) -> bool {
        match self {
            Self::Flow { class, egress, .. } => {
                *class == PrecedenceClass::RouteRule(RouteRole::Secondary)
                    || *egress == EgressConstraint::OnlyVia(EgressRef::Secondary)
            }
            Self::Route { egress, .. } => *egress == EgressRef::Secondary,
        }
    }

    /// The link this steer sends its destination over, `None` when it says
    /// nothing about one.
    fn course(&self) -> Option<Course> {
        let of = |egress: &EgressRef| match egress {
            EgressRef::Primary => Some(Course::Primary),
            EgressRef::Secondary => Some(Course::Secondary),
            EgressRef::Adapter(_) => None,
        };
        match self {
            Self::Flow {
                egress: EgressConstraint::OnlyVia(egress),
                ..
            } => of(egress),
            Self::Flow {
                class: PrecedenceClass::RouteRule(RouteRole::Primary),
                ..
            } => Some(Course::Primary),
            Self::Flow {
                class: PrecedenceClass::RouteRule(RouteRole::Secondary),
                ..
            } => Some(Course::Secondary),
            Self::Flow { .. } => None,
            Self::Route { egress, .. } => of(egress),
        }
    }
}

/// One steered IPv4 destination: a host, or a network a rule pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Dst {
    Host(Ipv4Addr),
    Network(IpBlock),
}

type Steering = BTreeMap<Dst, Vec<Steer>>;

fn subnet_v4(dst: &DstMatch) -> Option<IpBlock> {
    match *dst {
        DstMatch::SubnetV4 { net, prefix } => IpBlock::new(IpAddr::V4(net), prefix),
        _ => None,
    }
}

fn steering_of(plan: &EnforcementPlan) -> Steering {
    let rule_networks: HashSet<IpBlock> = plan
        .flows
        .iter()
        .filter(|flow| matches!(flow.precedence.class, PrecedenceClass::RouteRule(_)))
        .filter_map(|flow| subnet_v4(&flow.flow.dst))
        .collect();
    let dst_of = |dst: &DstMatch| match *dst {
        DstMatch::HostV4(ip) => Some(Dst::Host(ip)),
        _ => subnet_v4(dst)
            .filter(|net| rule_networks.contains(net))
            .map(Dst::Network),
    };
    let mut steering: Steering = BTreeMap::new();
    let mut add = |dst: Dst, steer: Steer| {
        let entry = steering.entry(dst).or_default();
        if !entry.contains(&steer) {
            entry.push(steer);
        }
    };
    for flow in &plan.flows {
        if let Some(dst) = dst_of(&flow.flow.dst) {
            add(
                dst,
                Steer::Flow {
                    verdict: flow.verdict,
                    class: flow.precedence.class,
                    egress: flow.egress.clone(),
                    port: flow.flow.dst_port,
                    protocol: flow.flow.protocol,
                },
            );
        }
    }
    for route in &plan.routes {
        if let Some(dst) = dst_of(&route.dst) {
            add(
                dst,
                Steer::Route {
                    egress: route.egress.clone(),
                    table: route.table.clone(),
                },
            );
        }
    }
    steering
}

fn same_steering(a: &[Steer], b: &[Steer]) -> bool {
    a.len() == b.len() && a.iter().all(|s| b.contains(s))
}

/// The destinations whose connections should move: new or re-steered since
/// `previous`, plus every secondary-steered one when the link just came up.
/// `None` for `previous` means nothing was in force for this principal, so
/// everything is new. Sorted, so a log from one run compares with the next.
fn destinations_to_refresh(
    previous: Option<&Steering>,
    current: &Steering,
    tunnel_came_up: bool,
) -> Vec<Dst> {
    current
        .iter()
        .filter(|(dst, steer)| {
            (tunnel_came_up && steer.iter().any(Steer::onto_secondary))
                || previous
                    .and_then(|p| p.get(dst))
                    .is_none_or(|before| !same_steering(before, steer))
        })
        .map(|(dst, _)| *dst)
        .collect()
}

/// The destinations `previous` steered onto the additional link that `current`
/// no longer names at all. Sorted.
fn destinations_left_tunnel(previous: &Steering, current: &Steering) -> Vec<Dst> {
    previous
        .iter()
        .filter(|(dst, steer)| {
            !current.contains_key(dst) && steer.iter().any(Steer::onto_secondary)
        })
        .map(|(dst, _)| *dst)
        .collect()
}

/// The course of each destination whose steers agree on one link and none of
/// which blocks it: a block, or two links, leaves its connections no course.
fn courses_of(steering: &Steering) -> Courses {
    let mut courses = Courses::default();
    for (dst, steers) in steering {
        if steers.iter().any(|s| {
            matches!(
                s,
                Steer::Flow {
                    verdict: Verdict::Block,
                    ..
                }
            )
        }) {
            continue;
        }
        let mut said = steers.iter().filter_map(Steer::course);
        let Some(first) = said.next() else {
            continue;
        };
        if said.any(|c| c != first) {
            continue;
        }
        match *dst {
            Dst::Host(ip) => courses.insert_host(ip, first),
            Dst::Network(net) => courses.insert_network(net, first),
        }
    }
    courses
}

fn flow_targets(dsts: &[Dst]) -> FlowTargets {
    let mut hosts = Vec::new();
    let mut networks = Vec::new();
    for dst in dsts {
        match *dst {
            Dst::Host(ip) => hosts.push(ip),
            Dst::Network(net) => networks.push(net),
        }
    }
    FlowTargets::new(hosts, networks)
}

/// What one principal's connections last saw.
struct Remembered {
    steering: Steering,
    secondary_up: bool,
    /// Left out of the last pass. A plan that failed to read for one pass is
    /// not a sign-out: forgetting at once would reset every connection of
    /// theirs when the next pass reads it again.
    missed: bool,
}

#[derive(Default)]
struct Memory {
    principals: HashMap<String, Remembered>,
    /// A pass was in force without its routes; the next one diffs even if
    /// the plans did not change.
    behind: bool,
}

/// Tears down each principal's connections to destinations whose steering an
/// applied pass changed.
pub struct PlanFlowReset {
    reset: Arc<dyn StaleFlowReset>,
    cache: Arc<dyn FqdnCacheLookup>,
    memory: Mutex<Memory>,
}

impl PlanFlowReset {
    #[must_use]
    pub fn new(reset: Arc<dyn StaleFlowReset>, cache: Arc<dyn FqdnCacheLookup>) -> Self {
        Self {
            reset,
            cache,
            memory: Mutex::new(Memory::default()),
        }
    }

    /// A pass applied its filters but not its routes. Nothing is torn down —
    /// the application would reconnect over the path being replaced — and the
    /// change stays owed to the next pass that steers.
    pub fn defer(&self) {
        self.memory.lock().unwrap_or_else(|p| p.into_inner()).behind = true;
    }

    /// Call once `plans` are in force, filters AND routes. `changed` is the
    /// cycle's own "the plans differ from the last pass" — without it, a link
    /// edge or a deferred pass, nothing can have moved and nothing is read.
    /// `links` is read only for a principal with a connection to decide on.
    pub fn after_apply(
        &self,
        plans: &[EnforcementPlan],
        changed: bool,
        secondary_up: impl Fn(&UserPrincipal) -> bool,
        links: impl Fn(&UserPrincipal) -> FlowLinks,
    ) {
        let mut memory = self.memory.lock().unwrap_or_else(|p| p.into_inner());
        let came_up: HashSet<&str> = plans
            .iter()
            .filter(|plan| {
                secondary_up(&plan.principal)
                    && memory
                        .principals
                        .get(plan.principal.as_stored())
                        .is_some_and(|r| !r.secondary_up)
            })
            .map(|plan| plan.principal.as_stored())
            .collect();
        if !changed && !memory.behind && came_up.is_empty() {
            for plan in plans {
                if let Some(r) = memory.principals.get_mut(plan.principal.as_stored()) {
                    r.secondary_up = secondary_up(&plan.principal);
                }
            }
            return;
        }
        let mut next = HashMap::with_capacity(plans.len());
        for plan in plans {
            let sid = plan.principal.as_stored();
            let steering = steering_of(plan);
            let tunnel_came_up = came_up.contains(sid);
            let previous = memory.principals.remove(sid);
            let targets = destinations_to_refresh(
                previous.as_ref().map(|p| &p.steering),
                &steering,
                tunnel_came_up,
            );
            if !targets.is_empty() {
                let cause = if tunnel_came_up {
                    ResetCause::TunnelCameUp
                } else {
                    ResetCause::NewDestination
                };
                self.tear_down(sid, &targets, cause, || FlowPaths {
                    links: links(&plan.principal),
                    courses: courses_of(&steering),
                });
            }
            if let Some(previous) = previous.as_ref() {
                let left = destinations_left_tunnel(&previous.steering, &steering);
                if !left.is_empty() {
                    // A destination that left has no course: it goes wherever
                    // it runs on the principal's links.
                    self.tear_down(sid, &left, ResetCause::LeftTunnel, || FlowPaths {
                        links: links(&plan.principal),
                        courses: Courses::default(),
                    });
                }
            }
            next.insert(
                sid.to_owned(),
                Remembered {
                    steering,
                    secondary_up: secondary_up(&plan.principal),
                    missed: false,
                },
            );
        }
        // A principal absent for a second pass in a row is forgotten, so their
        // return finds every destination new: their sockets were opened under
        // no policy.
        for (sid, mut remembered) in memory.principals.drain() {
            if !remembered.missed {
                remembered.missed = true;
                next.insert(sid, remembered);
            }
        }
        memory.principals = next;
        memory.behind = false;
    }

    fn tear_down(
        &self,
        sid: &str,
        targets: &[Dst],
        cause: ResetCause,
        paths: impl FnOnce() -> FlowPaths,
    ) {
        let Some(outcome) = reset_owner_flows(
            self.reset.as_ref(),
            self.cache.as_ref(),
            sid,
            &flow_targets(targets),
            paths,
        ) else {
            return;
        };
        let decision = &outcome.decision;
        if decision.reset.is_empty() {
            tracing::debug!(
                target: "nrr::enforcement",
                sid,
                kept_shared = decision.kept_shared,
                kept_other_owner = decision.kept_other_owner,
                kept_unknown_owner = decision.kept_unknown_owner,
                kept_other_link = decision.kept_other_link,
                kept_on_course = decision.kept_on_course,
                "no connection on a changed destination is this principal's to reset",
            );
            return;
        }
        if outcome.torn_down == 0 {
            // The platform says why it refused; nothing here was reset.
            return;
        }
        log_reset_flows(Some(sid), &decision.reset, |_| (None, cause));
        tracing::info!(
            target: "nrr::enforcement",
            msg_key = "persid-apply-flows-torn-down",
            sid,
            torn_down = outcome.torn_down,
            destinations = targets.len(),
            tunnel_came_up = matches!(cause, ResetCause::TunnelCameUp),
            cause = cause.slug(),
            kept_shared = decision.kept_shared,
            kept_other_owner = decision.kept_other_owner,
            kept_unknown_owner = decision.kept_unknown_owner,
            kept_other_link = decision.kept_other_link,
            kept_on_course = decision.kept_on_course,
            "tore down connections that predate the steering this pass put in force — the application reconnects over the route the rule now assigns",
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;

    use nrr_platform_api::enforcement::{
        AppScope, Coverage, FlowMatch, FlowRule, Precedence, PrincipalScope, RouteIntent,
    };
    use nrr_platform_api::fake_ip::stale_flows::{EstablishedFlow, MockStaleFlowReset};

    use super::*;

    const UID: u32 = 1000;

    fn owner() -> UserPrincipal {
        UserPrincipal::from_linux_uid(UID)
    }

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    fn pin(dst: Ipv4Addr, role: RouteRole, ordinal: u32) -> FlowRule {
        FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(role),
                ordinal,
            },
            flow: FlowMatch {
                dst: DstMatch::HostV4(dst),
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope::User(owner()),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        }
    }

    fn route(dst: Ipv4Addr, egress: EgressRef) -> RouteIntent {
        RouteIntent {
            dst: DstMatch::HostV4(dst),
            egress,
            metric: 1,
            table: RouteTableRef::Principal(owner()),
        }
    }

    fn plan(flows: Vec<FlowRule>, routes: Vec<RouteIntent>) -> EnforcementPlan {
        EnforcementPlan {
            principal: owner(),
            flows,
            routes,
            policy_rules: Vec::new(),
        }
    }

    fn secondary(dst: Ipv4Addr, ordinal: u32) -> (FlowRule, RouteIntent) {
        (
            pin(dst, RouteRole::Secondary, ordinal),
            route(dst, EgressRef::Secondary),
        )
    }

    fn plan_of(entries: &[(FlowRule, RouteIntent)]) -> EnforcementPlan {
        plan(
            entries.iter().map(|(f, _)| f.clone()).collect(),
            entries.iter().map(|(_, r)| r.clone()).collect(),
        )
    }

    fn flow(remote: Ipv4Addr, port: u16, uid: u32) -> EstablishedFlow {
        EstablishedFlow {
            local: SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), port),
            remote: SocketAddrV4::new(remote, 443),
            owner: Some(UserPrincipal::from_linux_uid(uid).as_stored().to_owned()),
            pid: Some(4242),
            image: Some("browser".into()),
        }
    }

    struct Census(HashSet<Ipv4Addr>);

    impl FqdnCacheLookup for Census {
        fn ips_for_hostname(&self, _hostname: &str) -> Vec<std::net::IpAddr> {
            Vec::new()
        }
        fn hostnames_under_suffix(&self, _suffix: &str, _limit: usize) -> Vec<String> {
            Vec::new()
        }
        fn shared_direct_ips(&self) -> HashSet<Ipv4Addr> {
            self.0.clone()
        }
    }

    fn refresher(shared: &[Ipv4Addr]) -> (PlanFlowReset, Arc<MockStaleFlowReset>) {
        let mock = Arc::new(MockStaleFlowReset::new());
        let reset = PlanFlowReset::new(
            Arc::clone(&mock) as Arc<dyn StaleFlowReset>,
            Arc::new(Census(shared.iter().copied().collect())),
        );
        (reset, mock)
    }

    fn no_links(_: &UserPrincipal) -> FlowLinks {
        FlowLinks::default()
    }

    fn up(_: &UserPrincipal) -> bool {
        true
    }

    fn down(_: &UserPrincipal) -> bool {
        false
    }

    #[test]
    fn a_destination_a_change_adds_is_torn_down_and_one_already_in_force_is_not() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID), flow(ip(2), 50_001, UID)]);

        reset.after_apply(
            &[plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)])],
            true,
            up,
            no_links,
        );

        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_001, UID)]);
    }

    #[test]
    fn the_first_pass_finds_every_destination_new() {
        let (reset, mock) = refresher(&[]);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);
    }

    #[test]
    fn a_destination_moved_to_the_other_link_is_torn_down() {
        let (reset, mock) = refresher(&[]);
        let primary = plan(
            vec![pin(ip(1), RouteRole::Primary, 0)],
            vec![route(ip(1), EgressRef::Primary)],
        );
        reset.after_apply(&[primary], true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);

        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);

        assert_eq!(mock.reset_flows().len(), 1);
    }

    #[test]
    fn renumbering_a_rule_moves_nothing() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 7)])], true, up, no_links);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn a_destination_that_left_the_tunnel_is_torn_down() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(
            &[plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)])],
            true,
            up,
            no_links,
        );
        mock.set_flows(vec![flow(ip(1), 50_001, UID), flow(ip(2), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_000, UID)]);
    }

    #[test]
    fn a_destination_that_left_the_main_link_is_left_alone() {
        let (reset, mock) = refresher(&[]);
        let primary = plan(
            vec![pin(ip(1), RouteRole::Primary, 0)],
            vec![route(ip(1), EgressRef::Primary)],
        );
        reset.after_apply(&[primary], true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up, no_links);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn a_shared_direct_address_that_left_the_tunnel_is_spared() {
        let (reset, mock) = refresher(&[ip(2)]);
        reset.after_apply(&[plan_of(&[secondary(ip(2), 0)])], true, up, no_links);
        mock.set_flows(vec![flow(ip(2), 50_000, UID)]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up, no_links);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn a_principal_missing_from_one_pass_comes_back_without_a_reset() {
        let (reset, mock) = refresher(&[]);
        let p = plan_of(&[secondary(ip(1), 0)]);
        reset.after_apply(std::slice::from_ref(&p), true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[], true, up, no_links);
        reset.after_apply(&[p], true, up, no_links);
        assert!(mock.reset_flows().is_empty(), "{:?}", mock.reset_flows());
    }

    #[test]
    fn a_principal_gone_for_two_passes_returns_to_find_everything_new() {
        let (reset, mock) = refresher(&[]);
        let p = plan_of(&[secondary(ip(1), 0)]);
        reset.after_apply(std::slice::from_ref(&p), true, up, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[], true, up, no_links);
        reset.after_apply(&[], true, up, no_links);
        reset.after_apply(&[p], true, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);
    }

    #[test]
    fn an_unchanged_pass_reads_nothing() {
        let (reset, mock) = refresher(&[]);
        let p = plan_of(&[secondary(ip(1), 0)]);
        reset.after_apply(std::slice::from_ref(&p), true, up, no_links);
        let asked = mock.queried().len();
        reset.after_apply(&[p], false, up, no_links);
        assert_eq!(mock.queried().len(), asked, "the connection table was read");
    }

    #[test]
    fn only_the_owners_connections_go_and_a_shared_direct_address_is_spared() {
        let (reset, mock) = refresher(&[ip(2)]);
        mock.set_flows(vec![
            flow(ip(1), 50_000, UID),
            flow(ip(1), 50_001, UID + 1),
            flow(ip(2), 50_002, UID),
        ]);
        reset.after_apply(
            &[plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)])],
            true,
            up,
            no_links,
        );
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);
    }

    /// The addresses did not change while the link was down, so the diff
    /// alone would leave every socket opened meanwhile on the main link.
    #[test]
    fn the_link_coming_up_sweeps_what_is_steered_onto_it_and_nothing_else() {
        let (reset, mock) = refresher(&[]);
        let p = plan(
            vec![
                pin(ip(1), RouteRole::Secondary, 0),
                pin(ip(2), RouteRole::Primary, 1),
            ],
            vec![
                route(ip(1), EgressRef::Secondary),
                route(ip(2), EgressRef::Primary),
            ],
        );
        reset.after_apply(std::slice::from_ref(&p), true, down, no_links);
        reset.after_apply(std::slice::from_ref(&p), false, down, no_links);
        mock.set_flows(vec![flow(ip(1), 50_000, UID), flow(ip(2), 50_001, UID)]);

        reset.after_apply(std::slice::from_ref(&p), false, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);

        // Up and staying up is no edge.
        reset.after_apply(&[p], false, up, no_links);
        assert_eq!(mock.reset_flows().len(), 1);
    }

    /// Torn down before the route exists, the application would reconnect
    /// over the path being replaced; the change waits for a pass that steers.
    #[test]
    fn a_deferred_change_is_torn_down_by_the_next_steering_pass() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up, no_links);
        mock.set_flows(vec![flow(ip(2), 50_000, UID)]);

        reset.defer();
        assert!(mock.reset_flows().is_empty());

        let p = plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)]);
        reset.after_apply(&[p], false, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_000, UID)]);
    }

    fn subnet(dst: DstMatch, class: PrecedenceClass) -> FlowRule {
        FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence { class, ordinal: 0 },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope::User(owner()),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
        }
    }

    fn net24() -> DstMatch {
        DstMatch::SubnetV4 {
            net: Ipv4Addr::new(198, 51, 100, 0),
            prefix: 24,
        }
    }

    fn inside(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, last)
    }

    fn network_rule(role: RouteRole, egress: EgressRef) -> EnforcementPlan {
        plan(
            vec![subnet(net24(), PrecedenceClass::RouteRule(role))],
            vec![RouteIntent {
                dst: net24(),
                egress,
                metric: 1,
                table: RouteTableRef::Principal(owner()),
            }],
        )
    }

    #[test]
    fn a_network_a_rule_starts_pinning_tears_down_the_owners_flows_inside_it() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up, no_links);
        mock.set_flows(vec![
            flow(inside(9), 50_000, UID),
            flow(inside(10), 50_001, UID + 1),
            flow(Ipv4Addr::new(198, 51, 101, 9), 50_002, UID),
        ]);

        reset.after_apply(
            &[network_rule(RouteRole::Secondary, EgressRef::Secondary)],
            true,
            up,
            no_links,
        );

        assert_eq!(mock.reset_flows(), vec![flow(inside(9), 50_000, UID)]);
        assert_eq!(
            mock.queried_networks(),
            vec![IpBlock::parse("198.51.100.0/24").expect("network")]
        );
    }

    #[test]
    fn a_network_moved_to_the_other_link_is_torn_down_and_an_unchanged_one_is_not() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(
            &[network_rule(RouteRole::Primary, EgressRef::Primary)],
            true,
            up,
            no_links,
        );
        mock.set_flows(vec![flow(inside(9), 50_000, UID)]);
        reset.after_apply(
            &[network_rule(RouteRole::Primary, EgressRef::Primary)],
            true,
            up,
            no_links,
        );
        assert!(mock.reset_flows().is_empty(), "nothing moved");

        reset.after_apply(
            &[network_rule(RouteRole::Secondary, EgressRef::Secondary)],
            true,
            up,
            no_links,
        );
        assert_eq!(mock.reset_flows(), vec![flow(inside(9), 50_000, UID)]);
    }

    #[test]
    fn a_network_that_left_the_tunnel_is_torn_down_sparing_a_shared_direct_address() {
        let (reset, mock) = refresher(&[inside(7)]);
        reset.after_apply(
            &[network_rule(RouteRole::Secondary, EgressRef::Secondary)],
            true,
            up,
            no_links,
        );
        mock.set_flows(vec![
            flow(inside(9), 50_000, UID),
            flow(inside(7), 50_001, UID),
        ]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up, no_links);
        assert_eq!(mock.reset_flows(), vec![flow(inside(9), 50_000, UID)]);
    }

    /// Exemptions and route overlays are networks too, but no rule changed
    /// where their traffic goes: a LAN or a split-default half must never be
    /// swept.
    #[test]
    fn exemption_and_overlay_networks_are_never_swept() {
        let (reset, mock) = refresher(&[]);
        mock.set_flows(vec![
            flow(inside(9), 50_000, UID),
            flow(Ipv4Addr::new(10, 1, 2, 3), 50_001, UID),
        ]);
        let half = DstMatch::SubnetV4 {
            net: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 1,
        };
        let p = plan(
            vec![subnet(net24(), PrecedenceClass::CatchAllExempt)],
            vec![RouteIntent {
                dst: half,
                egress: EgressRef::Secondary,
                metric: 1,
                table: RouteTableRef::Main,
            }],
        );
        reset.after_apply(&[p], true, up, no_links);
        assert!(mock.reset_flows().is_empty());
        assert!(mock.queried_networks().is_empty());
    }

    /// A connection on a tunnel the user runs beside ours, or already on the
    /// link its destination is steered onto, has nowhere new to go.
    #[test]
    fn a_connection_on_another_link_or_already_on_course_is_spared() {
        let main_link = Ipv4Addr::new(192, 0, 2, 1);
        let tunnel_link = Ipv4Addr::new(198, 51, 100, 41);
        let corporate_link = Ipv4Addr::new(172, 16, 0, 150);
        let links = |_: &UserPrincipal| {
            FlowLinks::new(
                vec![
                    (IpAddr::V4(main_link), 2),
                    (IpAddr::V4(tunnel_link), 3),
                    (IpAddr::V4(corporate_link), 4),
                ],
                Some(2),
                Some(3),
            )
        };
        let via = |local: Ipv4Addr, remote: Ipv4Addr, port: u16| EstablishedFlow {
            local: SocketAddrV4::new(local, port),
            ..flow(remote, port, UID)
        };
        let (reset, mock) = refresher(&[]);
        let stranded = via(main_link, ip(1), 50_000);
        mock.set_flows(vec![
            stranded.clone(),
            via(tunnel_link, ip(1), 50_001),
            via(corporate_link, ip(1), 50_002),
            via(main_link, ip(2), 50_003),
            via(corporate_link, ip(2), 50_004),
        ]);
        let p = plan(
            vec![
                pin(ip(1), RouteRole::Secondary, 0),
                pin(ip(2), RouteRole::Primary, 1),
            ],
            vec![
                route(ip(1), EgressRef::Secondary),
                route(ip(2), EgressRef::Primary),
            ],
        );

        reset.after_apply(&[p], true, up, links);

        assert_eq!(mock.reset_flows(), vec![stranded]);
    }

    #[test]
    fn a_blocked_destination_has_no_course_and_goes_on_any_of_the_owners_links() {
        let mut blocked = pin(ip(1), RouteRole::Secondary, 0);
        blocked.verdict = Verdict::Block;
        let steering = steering_of(&plan(
            vec![blocked],
            vec![route(ip(1), EgressRef::Secondary)],
        ));
        assert_eq!(courses_of(&steering).of(ip(1)), None);

        let both_ways = steering_of(&plan(
            vec![pin(ip(2), RouteRole::Primary, 0)],
            vec![route(ip(2), EgressRef::Secondary)],
        ));
        assert_eq!(
            courses_of(&both_ways).of(ip(2)),
            None,
            "two links, no course"
        );
    }
}
