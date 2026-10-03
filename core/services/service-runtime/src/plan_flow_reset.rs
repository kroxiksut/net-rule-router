//! Tearing down the connections an applied plan change left on their old path,
//! for platforms whose apply is one whole-plan pass ([`PrincipalEnforcementCycle`]).
//!
//! A socket keeps the path it was opened on: the page the user just added a
//! rule for goes on loading over the old link until something breaks it. The
//! trigger here is the plan itself — a host destination whose steering differs
//! from the steering last made visible to connections, or, when the additional
//! link has just become usable, every destination steered onto it (its
//! addresses did not change while it was down, so the diff alone finds
//! nothing). Who may be cut is [`flows_to_reset`]'s decision, the same one the
//! per-SID activation path makes: the plan's owner only, nothing to an address
//! the shared-IP census has seen serving a direct host.
//!
//! A destination that LEFT the plan is torn down only if it was steered onto the
//! additional link: its route is gone, yet the socket keeps the tunnel's source
//! address and hangs until a timeout. One that left the main link keeps its
//! interface and goes on working, so it is left alone.
//!
//! [`PrincipalEnforcementCycle`]: crate::principal_enforcement::PrincipalEnforcementCycle

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use nrr_platform_api::enforcement::{
    DstMatch, EgressConstraint, EgressRef, EnforcementPlan, L4Proto, PrecedenceClass,
    RouteTableRef, UserPrincipal, Verdict,
};
use nrr_platform_api::fake_ip::stale_flows::StaleFlowReset;
use nrr_shared::RouteRole;

use crate::flow_reset_log::{log_reset_flows, ResetCause};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::routed_host_flow_refresh::flows_to_reset;

/// How a plan treats one IPv4 host — what a connection to it would notice
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
}

type Steering = BTreeMap<Ipv4Addr, Vec<Steer>>;

fn steering_of(plan: &EnforcementPlan) -> Steering {
    let mut steering: Steering = BTreeMap::new();
    let mut add = |ip: Ipv4Addr, steer: Steer| {
        let entry = steering.entry(ip).or_default();
        if !entry.contains(&steer) {
            entry.push(steer);
        }
    };
    for flow in &plan.flows {
        if let DstMatch::HostV4(ip) = flow.flow.dst {
            add(
                ip,
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
        if let DstMatch::HostV4(ip) = route.dst {
            add(
                ip,
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
) -> Vec<Ipv4Addr> {
    current
        .iter()
        .filter(|(ip, steer)| {
            (tunnel_came_up && steer.iter().any(Steer::onto_secondary))
                || previous
                    .and_then(|p| p.get(ip))
                    .is_none_or(|before| !same_steering(before, steer))
        })
        .map(|(ip, _)| *ip)
        .collect()
}

/// The destinations `previous` steered onto the additional link that `current`
/// no longer names at all. Sorted.
fn destinations_left_tunnel(previous: &Steering, current: &Steering) -> Vec<Ipv4Addr> {
    previous
        .iter()
        .filter(|(ip, steer)| !current.contains_key(ip) && steer.iter().any(Steer::onto_secondary))
        .map(|(ip, _)| *ip)
        .collect()
}

/// What one principal's connections last saw.
struct Remembered {
    steering: Steering,
    secondary_up: bool,
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
    pub fn after_apply(
        &self,
        plans: &[EnforcementPlan],
        changed: bool,
        secondary_up: impl Fn(&UserPrincipal) -> bool,
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
                self.tear_down(sid, &targets, cause);
            }
            if let Some(previous) = previous.as_ref() {
                let left = destinations_left_tunnel(&previous.steering, &steering);
                if !left.is_empty() {
                    self.tear_down(sid, &left, ResetCause::LeftTunnel);
                }
            }
            next.insert(
                sid.to_owned(),
                Remembered {
                    steering,
                    secondary_up: secondary_up(&plan.principal),
                },
            );
        }
        // A principal absent from the pass is forgotten, so their return finds
        // every destination new: their sockets were opened under no policy.
        memory.principals = next;
        memory.behind = false;
    }

    fn tear_down(&self, sid: &str, targets: &[Ipv4Addr], cause: ResetCause) {
        let candidates = self.reset.established_flows_to(targets);
        if candidates.is_empty() {
            return;
        }
        // Read only when something is connected: the census is a query.
        let decision = flows_to_reset(
            candidates,
            sid,
            &self.cache.shared_direct_ips(),
            // No anchor: an apply routes addresses, it offers nothing.
            &HashSet::new(),
        );
        if decision.reset.is_empty() {
            tracing::debug!(
                target: "nrr::enforcement",
                sid,
                kept_shared = decision.kept_shared,
                kept_other_owner = decision.kept_other_owner,
                kept_unknown_owner = decision.kept_unknown_owner,
                "no connection on a changed destination is this principal's to reset",
            );
            return;
        }
        let torn_down = self.reset.reset_established(&decision.reset);
        if torn_down == 0 {
            // The platform says why it refused; nothing here was reset.
            return;
        }
        log_reset_flows(Some(sid), &decision.reset, |_| (None, cause));
        tracing::info!(
            target: "nrr::enforcement",
            msg_key = "persid-apply-flows-torn-down",
            sid,
            torn_down,
            destinations = targets.len(),
            tunnel_came_up = matches!(cause, ResetCause::TunnelCameUp),
            cause = cause.slug(),
            kept_shared = decision.kept_shared,
            kept_other_owner = decision.kept_other_owner,
            kept_unknown_owner = decision.kept_unknown_owner,
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
            principal: PrincipalScope(Some(owner())),
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

    fn up(_: &UserPrincipal) -> bool {
        true
    }

    fn down(_: &UserPrincipal) -> bool {
        false
    }

    #[test]
    fn a_destination_a_change_adds_is_torn_down_and_one_already_in_force_is_not() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);
        mock.set_flows(vec![flow(ip(1), 50_000, UID), flow(ip(2), 50_001, UID)]);

        reset.after_apply(
            &[plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)])],
            true,
            up,
        );

        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_001, UID)]);
    }

    #[test]
    fn the_first_pass_finds_every_destination_new() {
        let (reset, mock) = refresher(&[]);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);
    }

    #[test]
    fn a_destination_moved_to_the_other_link_is_torn_down() {
        let (reset, mock) = refresher(&[]);
        let primary = plan(
            vec![pin(ip(1), RouteRole::Primary, 0)],
            vec![route(ip(1), EgressRef::Primary)],
        );
        reset.after_apply(&[primary], true, up);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);

        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);

        assert_eq!(mock.reset_flows().len(), 1);
    }

    #[test]
    fn renumbering_a_rule_moves_nothing() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 7)])], true, up);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn a_destination_that_left_the_tunnel_is_torn_down() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(
            &[plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)])],
            true,
            up,
        );
        mock.set_flows(vec![flow(ip(1), 50_001, UID), flow(ip(2), 50_000, UID)]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);
        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_000, UID)]);
    }

    #[test]
    fn a_destination_that_left_the_main_link_is_left_alone() {
        let (reset, mock) = refresher(&[]);
        let primary = plan(
            vec![pin(ip(1), RouteRole::Primary, 0)],
            vec![route(ip(1), EgressRef::Primary)],
        );
        reset.after_apply(&[primary], true, up);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn a_shared_direct_address_that_left_the_tunnel_is_spared() {
        let (reset, mock) = refresher(&[ip(2)]);
        reset.after_apply(&[plan_of(&[secondary(ip(2), 0)])], true, up);
        mock.set_flows(vec![flow(ip(2), 50_000, UID)]);
        reset.after_apply(&[plan(Vec::new(), Vec::new())], true, up);
        assert!(mock.reset_flows().is_empty());
    }

    #[test]
    fn an_unchanged_pass_reads_nothing() {
        let (reset, mock) = refresher(&[]);
        let p = plan_of(&[secondary(ip(1), 0)]);
        reset.after_apply(std::slice::from_ref(&p), true, up);
        let asked = mock.queried().len();
        reset.after_apply(&[p], false, up);
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
        reset.after_apply(std::slice::from_ref(&p), true, down);
        reset.after_apply(std::slice::from_ref(&p), false, down);
        mock.set_flows(vec![flow(ip(1), 50_000, UID), flow(ip(2), 50_001, UID)]);

        reset.after_apply(std::slice::from_ref(&p), false, up);
        assert_eq!(mock.reset_flows(), vec![flow(ip(1), 50_000, UID)]);

        // Up and staying up is no edge.
        reset.after_apply(&[p], false, up);
        assert_eq!(mock.reset_flows().len(), 1);
    }

    /// Torn down before the route exists, the application would reconnect
    /// over the path being replaced; the change waits for a pass that steers.
    #[test]
    fn a_deferred_change_is_torn_down_by_the_next_steering_pass() {
        let (reset, mock) = refresher(&[]);
        reset.after_apply(&[plan_of(&[secondary(ip(1), 0)])], true, up);
        mock.set_flows(vec![flow(ip(2), 50_000, UID)]);

        reset.defer();
        assert!(mock.reset_flows().is_empty());

        let p = plan_of(&[secondary(ip(1), 0), secondary(ip(2), 1)]);
        reset.after_apply(&[p], false, up);
        assert_eq!(mock.reset_flows(), vec![flow(ip(2), 50_000, UID)]);
    }

    #[test]
    fn a_principal_who_returns_finds_every_destination_new() {
        let (reset, mock) = refresher(&[]);
        let p = plan_of(&[secondary(ip(1), 0)]);
        reset.after_apply(std::slice::from_ref(&p), true, up);
        reset.after_apply(&[], true, up);
        mock.set_flows(vec![flow(ip(1), 50_000, UID)]);
        reset.after_apply(&[p], true, up);
        assert_eq!(mock.reset_flows().len(), 1);
    }
}
