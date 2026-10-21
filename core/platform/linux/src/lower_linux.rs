//! Linux LOWERING of the neutral [`EnforcementPlan`] into an [`NftRuleset`].
//!
//! The Linux half of the same seam `lower_windows` implements. Windows
//! arbitrates with weight bands and lets every filter be evaluated; nftables
//! evaluates a chain top-down and stops at the first terminal verdict. So the
//! whole of the arbitration is expressed here as ORDER: sort by precedence rank
//! (higher first), then by the planner's ordinal, and emit terminal rules.
//!
//! Pure by construction — no kernel, no root, no `nft` binary — which is why
//! this half is unit-tested on any dev host. Delivering the ruleset to the
//! kernel is a separate concern (`nft_apply`).
//!
//! ## What does not lower, and why that is not silent
//!
//! [`AppScope::Program`] carries Windows executable paths; nftables has no
//! per-exe match, so an app-scoped rule cannot be expressed here. Those rules
//! are REPORTED as unsupported rather than dropped quietly — see
//! [`LoweredPlan::unsupported`]. The product enforces app rules on Linux
//! through observed destinations until a mark-based mechanism lands, and the
//! caller needs to know which rules that applies to.

use nrr_platform_api::enforcement::{
    AppScope, DstMatch, EgressConstraint, EgressRef, EnforcementPlan, FlowMatch, FlowRule, L4Proto,
    PrincipalScope, UserPrincipal, Verdict,
};
use nrr_platform_api::own_traffic::OWN_TRAFFIC_MARK;

use crate::drop_tag::{DropKind, DropTag};
use crate::nft_ir::{NftFamily, NftMatch, NftRule, NftRuleset, NftVerdict};

/// Table name we own. Everything this product installs lives inside it, so
/// teardown is one `delete table` and never touches a rule someone else wrote.
pub const NRR_TABLE: &str = "nrr";

/// Output-hook chain: the packet's egress interface is known there, which is
/// what an egress pin needs.
pub const NRR_CHAIN: &str = "output";

/// Which interface names the plan's neutral egress references resolve to. The
/// plan never names a device; resolution happens here, at lowering time, from
/// facts read fresh — the same rule the Windows side follows with LUIDs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EgressNames {
    pub primary: Option<String>,
    pub secondary: Option<String>,
}

impl EgressNames {
    fn resolve(&self, egress: &EgressRef) -> Option<String> {
        match egress {
            EgressRef::Primary => self.primary.clone(),
            EgressRef::Secondary => self.secondary.clone(),
            EgressRef::Adapter(id) => Some(id.0.clone()),
        }
    }

    /// Resolve the two bound adapters against the interfaces that exist RIGHT
    /// NOW, matching on the saved name and accepting only a link that is up.
    ///
    /// A binding that no longer resolves comes back as `None`, and the lowering
    /// then reports its rules unsupported rather than emitting them unpinned.
    /// That is the whole point of resolving per reconcile: a down or renamed
    /// link must remove the pin, not silently widen it to "any interface".
    pub fn resolve_from_adapters(
        adapters: &[nrr_platform_api::adapters::AdapterInfo],
        bound_primary: Option<&str>,
        bound_secondary: Option<&str>,
    ) -> Self {
        Self {
            primary: bound_primary.and_then(|name| live_link_named(adapters, name)),
            secondary: bound_secondary.and_then(|name| live_link_named(adapters, name)),
        }
    }
}

/// Find a link by the name the binding was saved under. Linux reports the link
/// name in both fields, so either may carry it; the saved name is what the user
/// saw, which is why it — not an index — is the identity.
fn live_link_named(
    adapters: &[nrr_platform_api::adapters::AdapterInfo],
    name: &str,
) -> Option<String> {
    adapters
        .iter()
        .find(|a| {
            (a.friendly_name == name || a.adapter_name == name)
                && a.oper_status == nrr_platform_api::adapters::IfOperStatus::Up
        })
        .map(|a| {
            if a.friendly_name.is_empty() {
                a.adapter_name.clone()
            } else {
                a.friendly_name.clone()
            }
        })
}

/// A rule the Linux mechanism cannot express, with the reason. Returned rather
/// than dropped: an enforcement backend that silently ignores part of a plan is
/// indistinguishable from one that enforces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedRule {
    /// Index into `plan.flows`.
    pub index: usize,
    /// Stored principal of the plan the rule came from. With several users'
    /// plans lowered into one ruleset, an index alone no longer says whose rule
    /// went unenforced — and that is the first thing an operator asks.
    pub principal: String,
    pub reason: UnsupportedReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsupportedReason {
    /// The rule is scoped to a named program; nftables has no per-executable
    /// match. Enforced via observed destinations instead.
    AppScoped { key: String },
    /// The rule pins egress to an interface the caller could not resolve to a
    /// name (adapter absent right now).
    UnresolvedEgress,
    /// The rule is scoped to a principal with no Unix uid (a Windows SID read
    /// from a migrated store). Emitting it anyway would drop the user condition
    /// and apply one person's policy to everyone on the machine.
    UnresolvablePrincipal { stored: String },
}

/// The result of lowering: the ruleset to apply, plus what could not be
/// expressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoweredPlan {
    pub ruleset: NftRuleset,
    pub unsupported: Vec<UnsupportedRule>,
}

/// Lower a neutral plan into the ruleset that enforces it.
///
/// Ordering is the mechanism: rules are emitted in descending precedence rank,
/// and within a band in ascending ordinal — the planner's canonical order. A
/// terminal `accept`/`drop` at the first match then reproduces the arbitration
/// Windows gets from weight bands.
pub fn lower_plan(plan: &EnforcementPlan, egress: &EgressNames) -> LoweredPlan {
    lower_plans(std::slice::from_ref(plan), egress)
}

/// Lower the plans of EVERY active principal into ONE ruleset.
///
/// Applying a table is a whole-table replacement, so a per-plan apply would let
/// the second user's policy erase the first user's. Their rules are safe to
/// interleave because each carries `meta skuid`: a rule scoped to one uid cannot
/// match another user's packet, whatever order it sits in.
///
/// Arbitration within each plan is preserved exactly — the sort is stable on
/// (rank, ordinal) and falls back to the plan's own position, so a user's rules
/// keep the relative order their policy assigned them.
pub fn lower_plans(plans: &[EnforcementPlan], egress: &EgressNames) -> LoweredPlan {
    let scoped: Vec<ScopedPlan<'_>> = plans
        .iter()
        .map(|plan| ScopedPlan { plan, egress })
        .collect();
    lower_scoped(&scoped)
}

/// One principal's plan together with the interface names ITS bindings resolve
/// to.
///
/// Two users can route through different secondaries, so a single pair of names
/// for the whole ruleset would pin one of them to the other's link. The egress
/// travels with the plan for that reason.
pub struct ScopedPlan<'a> {
    pub plan: &'a EnforcementPlan,
    pub egress: &'a EgressNames,
}

/// Whose plan speaks for the machine's service accounts, and which uids those
/// are on this machine. The default lowers no service-account rule at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceAccountScope {
    /// The route-table owner: only its plan's service-account rules lower.
    pub owner: Option<UserPrincipal>,
    /// Sorted, disjoint inclusive uid ranges
    /// ([`crate::service_account_uids::service_account_uids`]).
    pub uids: Vec<(u32, u32)>,
}

impl ServiceAccountScope {
    fn speaks_for(&self, plan: &EnforcementPlan) -> bool {
        !self.uids.is_empty() && self.owner.as_ref() == Some(&plan.principal)
    }
}

/// Lower plans that each carry their own egress resolution.
pub fn lower_scoped(plans: &[ScopedPlan<'_>]) -> LoweredPlan {
    lower_scoped_with(plans, &ServiceAccountScope::default())
}

/// [`lower_scoped`], with the route-table owner's service-account rules
/// lowered onto `service_accounts.uids`.
///
/// Every other plan's service-account rules are dropped: one owner speaks for
/// the machine, and a second set would pin system traffic to two tunnels.
/// Every non-empty chain opens with an accept for our own mark: the service
/// runs as a service account, and its relay, resolver and probes must leave by
/// the link they chose. root's flows never lower ([`is_root_user`]); its
/// routes are applied like anyone's.
pub fn lower_scoped_with(
    plans: &[ScopedPlan<'_>],
    service_accounts: &ServiceAccountScope,
) -> LoweredPlan {
    let mut indexed: Vec<(usize, usize, &FlowRule)> = plans
        .iter()
        .enumerate()
        .flat_map(|(plan_idx, scoped)| {
            let speaks = service_accounts.speaks_for(scoped.plan);
            scoped
                .plan
                .flows
                .iter()
                .enumerate()
                .filter(move |(_, flow)| {
                    (speaks
                        || !matches!(
                            flow.principal,
                            PrincipalScope::ServiceAccounts | PrincipalScope::Forwarded
                        ))
                        && !is_root_user(flow)
                })
                .map(move |(flow_idx, flow)| (plan_idx, flow_idx, flow))
        })
        .collect();
    // Higher rank first; ties broken by the planner's ordinal, then by original
    // position so the output is stable for identical input (re-apply must be a
    // no-op, and a churning ruleset would defeat that).
    indexed.sort_by(|(ap, ai, a), (bp, bi, b)| {
        b.precedence
            .class
            .rank()
            .cmp(&a.precedence.class.rank())
            .then(a.precedence.ordinal.cmp(&b.precedence.ordinal))
            .then(ap.cmp(bp))
            .then(ai.cmp(bi))
    });

    let mut rules: Vec<NftRule> = Vec::new();
    let mut forward: Vec<NftRule> = Vec::new();
    let mut unsupported = Vec::new();

    for (plan_idx, index, flow) in indexed {
        let lowered = lower_flow(flow, plans[plan_idx].egress, &service_accounts.uids);
        if flow.principal == PrincipalScope::Forwarded {
            // No process to tell about a forwarded packet's drop.
            forward.extend(lowered.rules.into_iter().map(|mut rule| {
                if rule.verdict.is_drop() {
                    rule.verdict = NftVerdict::Drop;
                }
                rule
            }));
        } else {
            rules.extend(lowered.rules);
        }
        if let Some(reason) = lowered.unsupported {
            unsupported.push(UnsupportedRule {
                index,
                principal: plans[plan_idx].plan.principal.as_stored().to_owned(),
                reason,
            });
        }
    }
    let mut rules = crate::nft_merge::fold_into_sets(prune_unreachable(rules));
    if !rules.is_empty() {
        rules.insert(
            0,
            NftRule {
                matches: vec![NftMatch::Mark(OWN_TRAFFIC_MARK)],
                verdict: NftVerdict::Accept,
                comment: "own-traffic".to_owned(),
            },
        );
    }

    let mut forward = crate::nft_merge::fold_into_sets(prune_unreachable(forward));
    if !forward.is_empty() {
        // The forward hook sees both directions. A reply to a flow a container
        // was allowed to open (local network, a primary host, its DNS) comes
        // back addressed to the container, which no exemption names; the
        // original direction stays judged, so nothing leaves that was held.
        forward.insert(
            0,
            NftRule {
                matches: vec![NftMatch::CtReply],
                verdict: NftVerdict::Accept,
                comment: "forwarded-reply".to_owned(),
            },
        );
    }

    LoweredPlan {
        ruleset: NftRuleset {
            family: NftFamily::Inet,
            table: NRR_TABLE.to_owned(),
            chain: NRR_CHAIN.to_owned(),
            rules,
            forward,
        },
        unsupported,
    }
}

/// Whether `flow` is scoped to root. uid 0 is the daemon's own, sshd's and
/// every VPN client's: a rule on it judges the daemon's DNS forwarding and each
/// SSH reply, so root is not a person for filtering.
fn is_root_user(flow: &FlowRule) -> bool {
    match &flow.principal {
        PrincipalScope::User(principal) => principal.as_unix_uid() == Some(0),
        _ => false,
    }
}

/// Drop the rules no packet can ever reach.
///
/// Every verdict here is terminal, so an earlier rule whose conditions are a
/// SUBSET of a later one's already decided every packet the later one describes.
/// Two sources produce such rules and neither is a mistake: the plan states a
/// rule twice — once for the connect decision, once per packet — because Windows
/// judges those at two layers, and a blanket block makes the protocol-specific
/// blocks beneath it redundant. Keeping them would grow the ruleset a reader has
/// to reason about, with not one verdict changed.
fn prune_unreachable(rules: Vec<NftRule>) -> Vec<NftRule> {
    let mut kept: Vec<NftRule> = Vec::new();
    for rule in rules {
        let unreachable = kept
            .iter()
            .any(|earlier| earlier.matches.iter().all(|m| rule.matches.contains(m)));
        if !unreachable {
            kept.push(rule);
        }
    }
    kept
}

/// What one flow lowered to: the rules to emit, and the reason it could not be
/// expressed in full.
///
/// Both halves at once is the case that matters: an egress pin whose interface
/// is gone loses its `accept`, but its leak-guard `drop` must stay. Reporting
/// the rule unsupported AND emitting nothing is fail-OPEN — the traffic the pin
/// existed to confine follows the default route instead, which is the leak the
/// pin was there to prevent.
struct LoweredFlow {
    rules: Vec<NftRule>,
    unsupported: Option<UnsupportedReason>,
}

impl LoweredFlow {
    fn rules(rules: Vec<NftRule>) -> Self {
        Self {
            rules,
            unsupported: None,
        }
    }

    fn unsupported(reason: UnsupportedReason) -> Self {
        Self {
            rules: Vec::new(),
            unsupported: Some(reason),
        }
    }
}

fn lower_flow(flow: &FlowRule, egress: &EgressNames, service_uids: &[(u32, u32)]) -> LoweredFlow {
    if let AppScope::Program { key, .. } = &flow.app {
        return LoweredFlow::unsupported(UnsupportedReason::AppScoped { key: key.clone() });
    }

    let mut base = Vec::new();
    match &flow.principal {
        PrincipalScope::User(principal) => {
            // Per-user matching is a plain condition here — the capability
            // Windows has to emulate with per-SID filter sets. A principal we
            // cannot express as a uid must FAIL the rule, never widen it:
            // dropping the condition turns one user's rule into a machine-wide
            // one.
            let Some(uid) = principal.as_unix_uid() else {
                return LoweredFlow::unsupported(UnsupportedReason::UnresolvablePrincipal {
                    stored: principal.as_stored().to_owned(),
                });
            };
            base.push(NftMatch::SkUid(uid));
        }
        // First, so a user's packet leaves the rule at its first comparison.
        PrincipalScope::ServiceAccounts => {
            if service_uids.is_empty() {
                return LoweredFlow::rules(Vec::new());
            }
            base.push(NftMatch::SkUidSet(service_uids.to_vec()));
        }
        // Matched by the hook it is lowered into, not by a condition.
        PrincipalScope::Machine | PrincipalScope::Forwarded => {}
    }
    base.extend(lower_flow_match(&flow.flow));

    let comment = rule_comment(flow);

    // The lockdown restated for one foreign link: a plain drop on that
    // interface, not the pin pair an `OnlyVia` permit means. A link that is
    // gone carries nothing, so there is nothing to drop.
    if flow.verdict == Verdict::Block
        && flow.precedence.class == nrr_platform_api::enforcement::PrecedenceClass::HardBlock
        && flow.precedence.ordinal >= nrr_platform_api::enforcement::DOH_FOREIGN_VETO_ORDINAL_BASE
    {
        if let EgressConstraint::OnlyVia(reference) = &flow.egress {
            let rules = egress
                .resolve(reference)
                .map(|device| {
                    let mut matches = base.clone();
                    matches.push(NftMatch::OutInterface(device));
                    NftRule {
                        matches,
                        verdict: verdict_of(flow),
                        comment: comment.clone(),
                    }
                })
                .into_iter()
                .collect();
            return LoweredFlow::rules(rules);
        }
    }

    // A pin on ANY destination is the blanket "everything through the tunnel"
    // permit; any exemption only spares. Either way the cut it spares from is
    // the posture's own block, stated lower down. A guard here would sit in the
    // exemption band and cut what a later exemption spares: the machine's own
    // escapes, or a home LAN in the range a corporate tunnel carries.
    let spares_only = flow.flow.dst == DstMatch::Any
        || (flow.verdict == Verdict::Permit
            && flow.precedence.class
                == nrr_platform_api::enforcement::PrecedenceClass::CatchAllExempt);

    match &flow.egress {
        EgressConstraint::Any => LoweredFlow::rules(vec![NftRule {
            matches: base,
            verdict: verdict_of(flow),
            comment,
        }]),
        // Whichever link carries it: the route says the kernel will encrypt
        // it. A lockdown veto restated for it drops just as plainly.
        EgressConstraint::UnderIpsecPolicy => {
            let mut matches = base;
            matches.push(NftMatch::RouteIpsec);
            LoweredFlow::rules(vec![NftRule {
                matches,
                verdict: verdict_of(flow),
                comment,
            }])
        }
        EgressConstraint::OnlyVia(reference) => {
            let Some(device) = egress.resolve(reference) else {
                // The pinned link is gone. The `accept` cannot be built without
                // an interface name, but the guard CAN: same destination, any
                // interface, dropped. Emitting nothing here would let the
                // traffic follow the default route — the leak the pin exists to
                // prevent, appearing at exactly the moment the pinned link
                // failed.
                if spares_only {
                    return LoweredFlow::unsupported(UnsupportedReason::UnresolvedEgress);
                }
                return LoweredFlow {
                    rules: vec![NftRule {
                        matches: base,
                        verdict: NftVerdict::DropReported(drop_tag(flow, true)),
                        comment: format!("{comment} leak-guard (pinned link absent)"),
                    }],
                    unsupported: Some(UnsupportedReason::UnresolvedEgress),
                };
            };
            let mut pinned = base.clone();
            pinned.push(NftMatch::OutInterface(device));
            let accept = NftRule {
                matches: pinned,
                verdict: NftVerdict::Accept,
                comment: format!("{comment} via"),
            };
            if spares_only {
                return LoweredFlow::rules(vec![accept]);
            }
            LoweredFlow::rules(vec![
                accept,
                // Same destination, any other interface: dropped. Without this
                // the pin would be advice — traffic would simply follow the
                // default route when the pinned link is down, which is the leak
                // the pin exists to prevent.
                NftRule {
                    matches: base,
                    verdict: NftVerdict::DropReported(drop_tag(flow, true)),
                    comment: format!("{comment} leak-guard"),
                },
            ])
        }
    }
}

fn lower_flow_match(flow: &FlowMatch) -> Vec<NftMatch> {
    let mut matches = Vec::new();
    match flow.dst {
        DstMatch::Any => {}
        DstMatch::HostV4(addr) => matches.push(NftMatch::DstV4 {
            net: addr,
            prefix: 32,
        }),
        DstMatch::HostV6(addr) => matches.push(NftMatch::DstV6 {
            net: addr,
            prefix: 128,
        }),
        DstMatch::SubnetV4 { net, prefix } => matches.push(NftMatch::DstV4 { net, prefix }),
        DstMatch::SubnetV6 { net, prefix } => matches.push(NftMatch::DstV6 { net, prefix }),
    }
    if let Some(proto) = flow.protocol {
        matches.push(NftMatch::Protocol(protocol_number(proto)));
    }
    if let Some(port) = flow.dst_port {
        matches.push(NftMatch::DstPort(port));
    }
    matches
}

/// IANA protocol numbers. Matching by number rather than by nft keyword keeps
/// `L4Proto::Other(n)` expressible with no special case.
const fn protocol_number(proto: L4Proto) -> u8 {
    match proto {
        L4Proto::Icmp => 1,
        L4Proto::Igmp => 2,
        L4Proto::Tcp => 6,
        L4Proto::Udp => 17,
        L4Proto::Gre => 47,
        L4Proto::Esp => 50,
        L4Proto::IcmpV6 => 58,
        L4Proto::Other(n) => n,
    }
}

/// Every drop we emit is reported: the observer cannot tell a dropped
/// connection from one never made, and the drop is the only place that knows.
fn verdict_of(flow: &FlowRule) -> NftVerdict {
    match flow.verdict {
        Verdict::Permit => NftVerdict::Accept,
        Verdict::Block => NftVerdict::DropReported(drop_tag(flow, false)),
    }
}

/// The role of a drop, from the band that produced it. `leak_guard` marks the
/// drop half of an egress pin, whatever its band.
fn drop_tag(flow: &FlowRule, leak_guard: bool) -> DropTag {
    use nrr_platform_api::enforcement::PrecedenceClass as P;
    let kind = if leak_guard {
        DropKind::Pin
    } else {
        match flow.precedence.class {
            P::KillSwitchBlock => DropKind::FailClosed,
            P::CatchAllBlock if matches!(flow.flow.dst, DstMatch::SubnetV6 { prefix: 0, .. }) => {
                DropKind::Ipv6Cut
            }
            P::CatchAllBlock => DropKind::BlockAll,
            P::DohBlock => DropKind::DnsLockdown,
            // The lockdown restated for a corporate link is still the lockdown.
            P::HardBlock
                if flow.precedence.ordinal
                    >= nrr_platform_api::enforcement::DOH_FOREIGN_VETO_ORDINAL_BASE =>
            {
                DropKind::DnsLockdown
            }
            // A veto the guard states for itself is not the user's rule.
            P::HardBlock
                if flow.precedence.ordinal
                    >= nrr_platform_api::enforcement::FOREIGN_PIN_VETO_ORDINAL_BASE =>
            {
                DropKind::FailClosed
            }
            P::HardBlock => DropKind::Rule,
            P::FakeIpPool => DropKind::RelayPool,
            P::RouteRule(_) | P::CatchAllExempt | P::KillSwitchPermit => DropKind::Other,
        }
    };
    DropTag {
        kind,
        system: flow.principal == PrincipalScope::ServiceAccounts,
    }
}

/// Provenance for the rule comment: which band and ordinal produced it. This is
/// what makes a live ruleset readable back against the plan.
fn rule_comment(flow: &FlowRule) -> String {
    format!(
        "{}#{}",
        band_slug(flow.precedence.class),
        flow.precedence.ordinal
    )
}

fn band_slug(class: nrr_platform_api::enforcement::PrecedenceClass) -> &'static str {
    use nrr_platform_api::enforcement::PrecedenceClass as P;
    use nrr_shared::RouteRole;
    match class {
        P::RouteRule(RouteRole::Primary) => "route-primary",
        P::RouteRule(RouteRole::Secondary) => "route-secondary",
        P::DohBlock => "doh-block",
        P::CatchAllBlock => "catch-all-block",
        P::CatchAllExempt => "catch-all-exempt",
        P::KillSwitchBlock => "kill-switch-block",
        P::KillSwitchPermit => "kill-switch-permit",
        P::FakeIpPool => "fake-ip-pool",
        P::HardBlock => "hard-block",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::enforcement::{Coverage, Precedence, PrecedenceClass, UserPrincipal};
    use nrr_shared::RouteRole;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    fn rule(class: PrecedenceClass, ordinal: u32, dst: DstMatch, verdict: Verdict) -> FlowRule {
        FlowRule {
            verdict,
            precedence: Precedence { class, ordinal },
            flow: FlowMatch {
                dst,
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope::Machine,
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
            observed_by_program: false,
        }
    }

    fn plan_of(flows: Vec<FlowRule>) -> EnforcementPlan {
        EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }
    }

    fn pin_drop() -> NftVerdict {
        NftVerdict::DropReported(DropTag::user(DropKind::Pin))
    }

    fn names() -> EgressNames {
        EgressNames {
            primary: Some("eth0".into()),
            secondary: Some("tun0".into()),
        }
    }

    /// The rules behind the accept for our own marked traffic, which opens
    /// every non-empty chain.
    fn policy_rules(lowered: &LoweredPlan) -> &[NftRule] {
        match lowered.ruleset.rules.split_first() {
            None => &[],
            Some((first, rest)) => {
                assert_eq!(first.matches, vec![NftMatch::Mark(OWN_TRAFFIC_MARK)]);
                assert_eq!(first.verdict, NftVerdict::Accept);
                rest
            }
        }
    }

    /// "Everything" over the tunnel: IPv6 leaving through it survives the
    /// family cut, IPv6 leaving any other way does not. The blanket permit
    /// names no family, so one `oifname` accept covers both.
    #[test]
    fn the_catch_all_lets_ipv6_out_through_the_tunnel_only() {
        let v6_all = DstMatch::SubnetV6 {
            net: std::net::Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        };
        let mut through_tunnel = rule(
            PrecedenceClass::CatchAllExempt,
            0,
            DstMatch::Any,
            Verdict::Permit,
        );
        through_tunnel.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        let mut flows = vec![through_tunnel];
        for coverage in [Coverage::ConnectOnly, Coverage::AllPackets] {
            let mut cut = rule(PrecedenceClass::CatchAllBlock, 0, v6_all, Verdict::Block);
            cut.coverage = coverage;
            flows.push(cut);
        }

        let lowered = lower_plan(&plan_of(flows), &names());
        let rules = policy_rules(&lowered);
        let accept = rules
            .iter()
            .position(|r| {
                r.verdict == NftVerdict::Accept
                    && r.matches.contains(&NftMatch::OutInterface("tun0".into()))
            })
            .expect("the tunnel accept");
        assert!(
            !rules[accept].matches.iter().any(|m| matches!(
                m,
                NftMatch::DstV4 { .. }
                    | NftMatch::DstV6 { .. }
                    | NftMatch::DstSetV4(_)
                    | NftMatch::DstSetV6(_)
            )),
            "family-agnostic: {:?}",
            rules[accept]
        );
        let cut = rules
            .iter()
            .position(|r| {
                r.verdict != NftVerdict::Accept
                    && r.matches.iter().any(|m| {
                        matches!(m, NftMatch::DstV6 { prefix: 0, .. } | NftMatch::DstSetV6(_))
                    })
            })
            .expect("the IPv6 cut");
        assert!(accept < cut, "the tunnel accept is matched first");
        assert!(
            rules[cut]
                .matches
                .iter()
                .all(|m| !matches!(m, NftMatch::OutInterface(_))),
            "the cut holds on every other link"
        );
    }

    /// The core of the port: Windows arbitrates by weight, Linux by position.
    /// A higher band must be emitted BEFORE a lower one whatever order the
    /// planner listed them in, or a catch-all block would shadow the exemption
    /// that is supposed to outrank it.
    #[test]
    fn higher_precedence_bands_are_emitted_first() {
        let plan = plan_of(vec![
            rule(
                PrecedenceClass::CatchAllBlock,
                0,
                DstMatch::Any,
                Verdict::Block,
            ),
            rule(
                PrecedenceClass::HardBlock,
                0,
                DstMatch::HostV4(v4(198, 51, 100, 1)),
                Verdict::Block,
            ),
            rule(
                PrecedenceClass::CatchAllExempt,
                0,
                DstMatch::HostV4(v4(127, 0, 0, 1)),
                Verdict::Permit,
            ),
        ]);

        let lowered = lower_plan(&plan, &names());
        let bands: Vec<&str> = policy_rules(&lowered)
            .iter()
            .map(|r| r.comment.as_str())
            .collect();
        assert_eq!(
            bands,
            vec!["hard-block#0", "catch-all-exempt#0", "catch-all-block#0"],
        );
    }

    #[test]
    fn within_one_band_the_planners_ordinal_decides() {
        let plan = plan_of(vec![
            rule(
                PrecedenceClass::RouteRule(RouteRole::Secondary),
                2,
                DstMatch::HostV4(v4(198, 51, 100, 3)),
                Verdict::Permit,
            ),
            rule(
                PrecedenceClass::RouteRule(RouteRole::Secondary),
                0,
                DstMatch::HostV4(v4(198, 51, 100, 1)),
                Verdict::Permit,
            ),
            rule(
                PrecedenceClass::RouteRule(RouteRole::Secondary),
                1,
                DstMatch::HostV4(v4(198, 51, 100, 2)),
                Verdict::Permit,
            ),
        ]);

        let lowered = lower_plan(&plan, &names());
        let comments: Vec<&str> = policy_rules(&lowered)
            .iter()
            .map(|r| r.comment.as_str())
            .collect();
        // The three fold into one set, which carries the comment of the rule
        // that came first: the lowest ordinal.
        assert_eq!(comments, vec!["route-secondary#0 +2"]);
    }

    /// A pin that only accepts on the right interface is advice, not a pin:
    /// when the tunnel drops, traffic would follow the default route. The
    /// scoped drop is what makes it leak-proof.
    #[test]
    fn an_egress_pin_lowers_to_accept_on_the_link_plus_a_scoped_drop() {
        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(203, 0, 113, 138)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let lowered = lower_plan(&plan_of(vec![pinned]), &names());
        assert_eq!(policy_rules(&lowered).len(), 2);

        let accept = &policy_rules(&lowered)[0];
        assert_eq!(accept.verdict, NftVerdict::Accept);
        assert!(accept
            .matches
            .contains(&NftMatch::OutInterface("tun0".into())));

        let guard = &policy_rules(&lowered)[1];
        assert_eq!(guard.verdict, pin_drop());
        assert!(
            !guard
                .matches
                .iter()
                .any(|m| matches!(m, NftMatch::OutInterface(_))),
            "the drop must not be tied to an interface, or it guards nothing",
        );
        // Same destination on both — the drop is scoped, not a blanket cut.
        assert!(guard.matches.contains(&NftMatch::DstV4 {
            net: v4(203, 0, 113, 138),
            prefix: 32,
        }));
    }

    /// A pinned address inside a foreign tunnel's permitted network is accepted
    /// by our tunnel and dropped on any other link, ahead of the tunnel's permit.
    #[test]
    fn a_pin_veto_is_matched_before_the_foreign_permit() {
        use nrr_platform_api::enforcement::{AdapterId, FOREIGN_PIN_VETO_ORDINAL_BASE};
        let mut permit = rule(
            PrecedenceClass::CatchAllExempt,
            0x0010_0000,
            DstMatch::SubnetV4 {
                net: v4(10, 77, 0, 0),
                prefix: 16,
            },
            Verdict::Permit,
        );
        permit.egress = EgressConstraint::OnlyVia(EgressRef::Adapter(AdapterId("corp0".into())));
        let mut veto = rule(
            PrecedenceClass::HardBlock,
            FOREIGN_PIN_VETO_ORDINAL_BASE,
            DstMatch::HostV4(v4(10, 77, 3, 4)),
            Verdict::Permit,
        );
        veto.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let lowered = lower_plan(&plan_of(vec![permit, veto]), &names());
        let rules = policy_rules(&lowered);
        let first_corp = rules
            .iter()
            .position(|r| r.comment.starts_with("catch-all-exempt"))
            .expect("the foreign permit is lowered");
        let pin_accept = rules
            .iter()
            .position(|r| r.comment.starts_with("hard-block") && r.verdict == NftVerdict::Accept)
            .expect("the veto accepts on our tunnel");
        let pin_drop_at = rules
            .iter()
            .position(|r| matches!(r.verdict, NftVerdict::DropReported(_)))
            .expect("the veto drops on any other link");
        assert!(pin_accept < first_corp && pin_drop_at < first_corp);
    }

    /// First-match walk of the output chain for one TCP/443 packet of `uid`.
    fn first_verdict(rules: &[NftRule], uid: u32, dst: Ipv4Addr, oif: &str) -> Option<NftVerdict> {
        first_verdict_of(rules, uid, dst, oif, false)
    }

    /// [`first_verdict`], for a packet whose route the kernel will encrypt
    /// under an IPsec policy when `ipsec` holds.
    fn first_verdict_of(
        rules: &[NftRule],
        uid: u32,
        dst: Ipv4Addr,
        oif: &str,
        ipsec: bool,
    ) -> Option<NftVerdict> {
        let hit = |m: &NftMatch| match m {
            NftMatch::SkUid(u) => *u == uid,
            NftMatch::SkUidSet(ranges) => ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&uid)),
            NftMatch::DstV4 { net, prefix } => {
                let mask = u32::MAX.checked_shl(32 - u32::from(*prefix)).unwrap_or(0);
                u32::from(*net) & mask == u32::from(dst) & mask
            }
            NftMatch::DstSetV4(blocks) => {
                blocks.iter().any(|b| b.contains(std::net::IpAddr::V4(dst)))
            }
            NftMatch::OutInterface(dev) => dev == oif,
            NftMatch::Protocol(p) => *p == 6,
            NftMatch::DstPort(p) => *p == 443,
            NftMatch::RouteIpsec => ipsec,
            NftMatch::DstV6 { .. }
            | NftMatch::DstSetV6(_)
            | NftMatch::Mark(_)
            | NftMatch::CtReply => false,
        };
        rules
            .iter()
            .find(|r| r.matches.iter().all(&hit))
            .map(|r| r.verdict)
    }

    /// A corporate tunnel that carries the same private range as the home LAN
    /// opens that range through itself and cuts nothing: the home LAN stays
    /// reachable through the uplink, while a pin keeps its own guard.
    #[test]
    fn a_foreign_permit_does_not_cut_a_home_lan_in_the_same_range() {
        use nrr_platform_api::enforcement::AdapterId;
        let user = PrincipalScope::User(UserPrincipal::from_linux_uid(1000));
        let mut corp = rule(
            PrecedenceClass::CatchAllExempt,
            0x0010_0000,
            DstMatch::SubnetV4 {
                net: v4(192, 168, 1, 0),
                prefix: 24,
            },
            Verdict::Permit,
        );
        corp.principal = user.clone();
        corp.egress = EgressConstraint::OnlyVia(EgressRef::Adapter(AdapterId("wg0".into())));
        let mut pin = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(203, 0, 113, 9)),
            Verdict::Permit,
        );
        pin.principal = user;
        pin.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let lowered = lower_plan(&plan_of(vec![corp, pin]), &names());
        let rules = policy_rules(&lowered);

        let lan = v4(192, 168, 1, 20);
        assert!(
            !matches!(
                first_verdict(rules, 1000, lan, "eth0"),
                Some(NftVerdict::Drop | NftVerdict::DropReported(_))
            ),
            "the home LAN is cut: {rules:?}"
        );
        assert_eq!(
            first_verdict(rules, 1000, lan, "wg0"),
            Some(NftVerdict::Accept)
        );
        assert!(
            rules
                .iter()
                .filter(|r| r.comment.starts_with("catch-all-exempt"))
                .all(|r| r.verdict == NftVerdict::Accept),
            "an exemption only spares: {rules:?}"
        );
        let pinned = v4(203, 0, 113, 9);
        assert_eq!(first_verdict(rules, 1000, pinned, "eth0"), Some(pin_drop()));
        assert_eq!(
            first_verdict(rules, 1000, pinned, "tun0"),
            Some(NftVerdict::Accept)
        );
    }

    /// The lockdown restated for a corporate link drops only what leaves
    /// through that interface, ahead of the link's permit, and is reported as
    /// the lockdown.
    #[test]
    fn the_lockdown_restated_for_a_foreign_link_drops_on_that_interface_only() {
        use nrr_platform_api::enforcement::{AdapterId, DOH_FOREIGN_VETO_ORDINAL_BASE};
        let corp = || EgressConstraint::OnlyVia(EgressRef::Adapter(AdapterId("corp0".into())));
        let mut permit = rule(
            PrecedenceClass::CatchAllExempt,
            0x0010_0000,
            DstMatch::SubnetV4 {
                net: v4(10, 77, 0, 0),
                prefix: 16,
            },
            Verdict::Permit,
        );
        permit.egress = corp();
        let mut veto = rule(
            PrecedenceClass::HardBlock,
            DOH_FOREIGN_VETO_ORDINAL_BASE,
            DstMatch::HostV4(v4(10, 77, 7, 7)),
            Verdict::Block,
        );
        veto.egress = corp();
        veto.flow.dst_port = Some(443);

        let lowered = lower_plan(&plan_of(vec![permit, veto]), &names());
        let rules = policy_rules(&lowered);
        let drops: Vec<_> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                matches!(r.verdict, NftVerdict::DropReported(_))
                    && r.matches
                        .iter()
                        .any(|m| matches!(m, NftMatch::OutInterface(_)))
            })
            .collect();
        assert_eq!(
            drops.len(),
            1,
            "one drop on the interface, no pin pair: {rules:?}"
        );
        let (at, drop) = drops[0];
        assert!(matches!(
            drop.verdict,
            NftVerdict::DropReported(DropTag {
                kind: DropKind::DnsLockdown,
                ..
            })
        ));
        assert!(
            rules
                .iter()
                .all(|r| r.verdict != NftVerdict::Accept || !r.comment.starts_with("hard-block")),
            "the restatement never accepts",
        );
        let permit_at = rules
            .iter()
            .position(|r| r.comment.starts_with("catch-all-exempt"))
            .expect("the foreign permit is lowered");
        assert!(at < permit_at, "matched before the link's permit");
    }

    /// What a policy-based IPsec VPN encrypts reaches a private network past
    /// the catch-all on the main link; the same packet without the policy, or
    /// to a public address, is still cut.
    #[test]
    fn ipsec_protected_traffic_is_spared_ahead_of_the_catch_all_block() {
        let user = PrincipalScope::User(UserPrincipal::from_linux_uid(1000));
        let private = [
            (v4(10, 0, 0, 0), 8),
            (v4(172, 16, 0, 0), 12),
            (v4(192, 168, 0, 0), 16),
        ];
        let mut flows: Vec<FlowRule> = private
            .iter()
            .enumerate()
            .map(|(n, &(net, prefix))| {
                let mut permit = rule(
                    PrecedenceClass::CatchAllExempt,
                    0x0019_0000 + n as u32,
                    DstMatch::SubnetV4 { net, prefix },
                    Verdict::Permit,
                );
                permit.principal = user.clone();
                permit.egress = EgressConstraint::UnderIpsecPolicy;
                permit
            })
            .collect();
        let mut block = rule(
            PrecedenceClass::CatchAllBlock,
            0,
            DstMatch::Any,
            Verdict::Block,
        );
        block.principal = user;
        flows.push(block);

        let lowered = lower_plan(&plan_of(flows), &names());
        assert!(lowered.unsupported.is_empty(), "{:?}", lowered.unsupported);
        let script = lowered.ruleset.to_nft_script();
        let spared = script
            .find(
                "meta skuid 1000 ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } rt ipsec exists accept",
            )
            .expect("one set rule for the private networks");
        let cut = script.find("catch-all-block").expect("the catch-all");
        assert!(spared < cut, "{script}");

        let rules = policy_rules(&lowered);
        let corp = v4(10, 20, 30, 40);
        assert_eq!(
            first_verdict_of(rules, 1000, corp, "eth0", true),
            Some(NftVerdict::Accept)
        );
        let cut = Some(NftVerdict::DropReported(DropTag::user(DropKind::BlockAll)));
        assert_eq!(first_verdict_of(rules, 1000, corp, "eth0", false), cut);
        assert_eq!(
            first_verdict_of(rules, 1000, v4(203, 0, 113, 9), "eth0", true),
            cut,
            "a policy over the whole internet keeps only the private networks"
        );
    }

    /// The lockdown restated for IPsec-protected traffic drops only what the
    /// kernel would encrypt, and before the permit that spares it.
    #[test]
    fn the_lockdown_restated_for_ipsec_traffic_drops_ahead_of_its_permit() {
        use nrr_platform_api::enforcement::DOH_FOREIGN_VETO_ORDINAL_BASE;
        let mut permit = rule(
            PrecedenceClass::CatchAllExempt,
            0x0019_0000,
            DstMatch::SubnetV4 {
                net: v4(10, 0, 0, 0),
                prefix: 8,
            },
            Verdict::Permit,
        );
        permit.egress = EgressConstraint::UnderIpsecPolicy;
        let mut veto = rule(
            PrecedenceClass::HardBlock,
            DOH_FOREIGN_VETO_ORDINAL_BASE,
            DstMatch::HostV4(v4(10, 77, 7, 7)),
            Verdict::Block,
        );
        veto.egress = EgressConstraint::UnderIpsecPolicy;
        veto.flow.dst_port = Some(443);

        let lowered = lower_plan(&plan_of(vec![permit, veto]), &names());
        let rules = policy_rules(&lowered);
        let drop_at = rules
            .iter()
            .position(|r| {
                r.verdict == NftVerdict::DropReported(DropTag::user(DropKind::DnsLockdown))
                    && r.matches.contains(&NftMatch::RouteIpsec)
            })
            .expect("the restated lockdown");
        let permit_at = rules
            .iter()
            .position(|r| {
                r.verdict == NftVerdict::Accept && r.matches.contains(&NftMatch::RouteIpsec)
            })
            .expect("the permit");
        assert!(drop_at < permit_at, "{rules:?}");
    }

    /// The chain is walked by every packet: a corporate link that pushes many
    /// networks folds into ONE rule over an anonymous set.
    #[test]
    fn a_foreign_links_networks_fold_into_one_set_rule() {
        use nrr_platform_api::enforcement::AdapterId;
        let flows: Vec<FlowRule> = (0..40u8)
            .map(|n| {
                let mut permit = rule(
                    PrecedenceClass::CatchAllExempt,
                    0x0010_0000 + u32::from(n),
                    DstMatch::SubnetV4 {
                        net: v4(10, n + 1, 0, 0),
                        prefix: 16,
                    },
                    Verdict::Permit,
                );
                permit.egress =
                    EgressConstraint::OnlyVia(EgressRef::Adapter(AdapterId("corp0".into())));
                permit
            })
            .collect();
        let lowered = lower_plan(&plan_of(flows), &names());
        let rules = policy_rules(&lowered);
        let corp: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.comment.starts_with("catch-all-exempt") && r.verdict == NftVerdict::Accept
            })
            .collect();
        assert_eq!(corp.len(), 1, "{corp:?}");
        assert!(corp[0]
            .matches
            .iter()
            .any(|m| matches!(m, NftMatch::DstSetV4(set) if set.len() == 40)));
    }

    /// A backend that silently ignores part of a plan looks exactly like one
    /// that enforces it. App-scoped rules have no nftables expression, so they
    /// come back named.
    #[test]
    fn app_scoped_rules_are_reported_unsupported_not_dropped_silently() {
        let mut app_rule = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::Any,
            Verdict::Permit,
        );
        app_rule.app = AppScope::Program {
            key: "messenger".into(),
            exe_paths: vec!["C:/messenger.exe".into()],
        };

        let lowered = lower_plan(&plan_of(vec![app_rule]), &names());
        assert!(policy_rules(&lowered).is_empty());
        assert_eq!(
            lowered.unsupported,
            vec![UnsupportedRule {
                index: 0,
                principal: "unix:uid:1000".into(),
                reason: UnsupportedReason::AppScoped {
                    key: "messenger".into()
                },
            }],
        );
    }

    /// Two logged-in users must both end up in the ruleset. Applying a table
    /// replaces it wholesale, so lowering one plan at a time and applying each
    /// would leave only whoever was applied last actually enforced.
    #[test]
    fn two_principals_are_lowered_into_one_ruleset() {
        let mut alice = plan_of(vec![rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(203, 0, 113, 1)),
            Verdict::Permit,
        )]);
        alice.flows[0].principal = PrincipalScope::User(UserPrincipal::from_linux_uid(1000));

        let mut bob = plan_of(vec![rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(198, 51, 100, 2)),
            Verdict::Permit,
        )]);
        bob.principal = UserPrincipal::from_linux_uid(1001);
        bob.flows[0].principal = PrincipalScope::User(UserPrincipal::from_linux_uid(1001));

        let lowered = lower_plans(&[alice, bob], &names());

        assert!(lowered.unsupported.is_empty());
        let uids: Vec<u32> = policy_rules(&lowered)
            .iter()
            .filter_map(|r| {
                r.matches.iter().find_map(|m| match m {
                    NftMatch::SkUid(uid) => Some(*uid),
                    _ => None,
                })
            })
            .collect();
        assert!(uids.contains(&1000) && uids.contains(&1001), "got {uids:?}");
    }

    /// A principal with no uid — a Windows SID surviving in a migrated store —
    /// must fail its rule, not lose the user condition. Without the condition
    /// the rule matches every packet on the host, which turns one person's
    /// routing policy into everyone's.
    #[test]
    fn a_principal_without_a_uid_fails_the_rule_instead_of_widening_it() {
        let mut foreign = plan_of(vec![rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(203, 0, 113, 1)),
            Verdict::Permit,
        )]);
        let sid = UserPrincipal::from_windows_sid("S-1-5-21-1-2-3-1001").expect("valid sid");
        foreign.principal = sid.clone();
        foreign.flows[0].principal = PrincipalScope::User(sid);

        let lowered = lower_plan(&foreign, &names());

        assert!(
            policy_rules(&lowered).is_empty(),
            "a rule that cannot be scoped to its user must not be applied at all",
        );
        assert!(matches!(
            lowered.unsupported.as_slice(),
            [UnsupportedRule {
                reason: UnsupportedReason::UnresolvablePrincipal { .. },
                ..
            }]
        ));
    }

    /// An unresolvable pin must not silently become an unpinned accept — that
    /// would route the very traffic the pin exists to contain over the wrong
    /// link.
    #[test]
    fn a_pin_to_an_absent_adapter_is_unsupported_never_an_unpinned_accept() {
        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(198, 51, 100, 9)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let absent = EgressNames {
            primary: Some("eth0".into()),
            secondary: None,
        };
        let lowered = lower_plan(&plan_of(vec![pinned]), &absent);
        // Never an unpinned ACCEPT — that is what would widen the rule. What
        // does stay is the leak guard: the destination the pin confined is
        // dropped rather than allowed to follow the default route.
        assert!(policy_rules(&lowered)
            .iter()
            .all(|r| r.verdict == pin_drop()));
        assert_eq!(policy_rules(&lowered).len(), 1);
        assert_eq!(
            lowered.unsupported,
            vec![UnsupportedRule {
                index: 0,
                principal: "unix:uid:1000".into(),
                reason: UnsupportedReason::UnresolvedEgress,
            }],
        );
    }

    fn adapter(
        name: &str,
        status: nrr_platform_api::adapters::IfOperStatus,
    ) -> nrr_platform_api::adapters::AdapterInfo {
        nrr_platform_api::adapters::AdapterInfo {
            index: 1,
            adapter_name: name.to_owned(),
            description: name.to_owned(),
            friendly_name: name.to_owned(),
            mac: None,
            interface_type: nrr_platform_api::adapters::InterfaceType::Ethernet,
            oper_status: status,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            gateways: Vec::new(),
        }
    }

    /// Resolving per reconcile is what makes a pin honest: when the bound link
    /// is down, the name must NOT resolve, so its rules are reported unsupported
    /// instead of being emitted without the interface condition — which would
    /// widen the pin to "any interface" exactly when the tunnel is gone.
    #[test]
    fn a_down_link_does_not_resolve_so_its_pin_cannot_widen() {
        use nrr_platform_api::adapters::IfOperStatus;
        let adapters = vec![
            adapter("eth0", IfOperStatus::Up),
            adapter("tun0", IfOperStatus::Down),
        ];
        let names = EgressNames::resolve_from_adapters(&adapters, Some("eth0"), Some("tun0"));
        assert_eq!(names.primary.as_deref(), Some("eth0"));
        assert_eq!(names.secondary, None);

        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(198, 51, 100, 9)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        let lowered = lower_plan(&plan_of(vec![pinned]), &names);
        // The pin cannot widen: no accept is emitted. Its guard stays, so a
        // link that went down blocks the traffic it carried instead of handing
        // it to the default route.
        assert_eq!(policy_rules(&lowered).len(), 1);
        assert_eq!(policy_rules(&lowered)[0].verdict, pin_drop());
        assert_eq!(
            lowered.unsupported[0].reason,
            UnsupportedReason::UnresolvedEgress
        );
    }

    #[test]
    fn a_binding_whose_link_no_longer_exists_resolves_to_nothing() {
        use nrr_platform_api::adapters::IfOperStatus;
        let adapters = vec![adapter("eth0", IfOperStatus::Up)];
        let names =
            EgressNames::resolve_from_adapters(&adapters, Some("eth0"), Some("wg0-renamed"));
        assert_eq!(names.secondary, None);
    }

    #[test]
    fn the_principal_becomes_a_uid_match() {
        let mut scoped = rule(
            PrecedenceClass::RouteRule(RouteRole::Primary),
            0,
            DstMatch::HostV4(v4(198, 51, 100, 8)),
            Verdict::Permit,
        );
        scoped.principal = PrincipalScope::User(UserPrincipal::from_linux_uid(1001));

        let lowered = lower_plan(&plan_of(vec![scoped]), &names());
        assert!(policy_rules(&lowered)[0]
            .matches
            .contains(&NftMatch::SkUid(1001)));
    }

    #[test]
    fn protocol_and_port_lower_to_conditions() {
        let mut dns = rule(
            PrecedenceClass::CatchAllExempt,
            0,
            DstMatch::Any,
            Verdict::Permit,
        );
        dns.flow.protocol = Some(L4Proto::Udp);
        dns.flow.dst_port = Some(53);

        let lowered = lower_plan(&plan_of(vec![dns]), &names());
        let matches = &policy_rules(&lowered)[0].matches;
        assert!(matches.contains(&NftMatch::Protocol(17)));
        assert!(matches.contains(&NftMatch::DstPort(53)));
    }

    /// Re-apply must be a no-op, so identical input has to produce a byte-identical
    /// ruleset — including for rules that tie on band AND ordinal.
    #[test]
    fn lowering_is_deterministic_for_identical_input() {
        let flows = vec![
            rule(
                PrecedenceClass::KillSwitchBlock,
                0,
                DstMatch::HostV4(v4(198, 51, 100, 5)),
                Verdict::Block,
            ),
            rule(
                PrecedenceClass::KillSwitchBlock,
                0,
                DstMatch::HostV4(v4(198, 51, 100, 6)),
                Verdict::Block,
            ),
        ];
        let first = lower_plan(&plan_of(flows.clone()), &names());
        let second = lower_plan(&plan_of(flows), &names());
        assert_eq!(first, second);
        assert_eq!(
            first.ruleset.to_nft_script(),
            second.ruleset.to_nft_script()
        );
    }

    /// The blanket "everything through the tunnel" permit must NOT bring a
    /// leak-guard with it: that guard blocks every destination, and sitting in
    /// the exemption band it would cut loopback, the LAN and the tunnel's own
    /// server before their exemptions are ever reached.
    #[test]
    fn a_pin_on_any_destination_emits_no_leak_guard() {
        let plan = EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows: vec![FlowRule {
                verdict: Verdict::Permit,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllExempt,
                    ordinal: 0,
                },
                flow: FlowMatch {
                    dst: DstMatch::Any,
                    dst_port: None,
                    protocol: None,
                },
                principal: PrincipalScope::User(UserPrincipal::from_linux_uid(1000)),
                app: AppScope::Any,
                egress: EgressConstraint::OnlyVia(EgressRef::Secondary),
                coverage: Coverage::ConnectOnly,
                observed_by_program: false,
            }],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let egress = EgressNames {
            primary: Some("eth0".to_owned()),
            secondary: Some("tun0".to_owned()),
        };

        let lowered = lower_plan(&plan, &egress);

        assert_eq!(
            policy_rules(&lowered).len(),
            1,
            "the guard would block everything"
        );
        assert_eq!(policy_rules(&lowered)[0].verdict, NftVerdict::Accept);
    }

    /// The plan states a rule twice — once for the connect decision, once per
    /// packet — because Windows judges those at two layers. nftables judges once,
    /// so the pair must collapse or every re-apply looks like a change.
    #[test]
    fn the_two_layer_mirror_collapses_into_one_rule() {
        let flow = |coverage| FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllBlock,
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope::User(UserPrincipal::from_linux_uid(1000)),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage,
            observed_by_program: false,
        };
        let plan = EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows: vec![flow(Coverage::ConnectOnly), flow(Coverage::AllPackets)],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };

        let lowered = lower_plan(&plan, &EgressNames::default());

        assert_eq!(policy_rules(&lowered).len(), 1);
    }

    /// A blanket drop settles every packet of that user, so the protocol-specific
    /// blocks beneath it decide nothing. Keeping them would grow a ruleset a
    /// reader has to reason about without changing a verdict.
    #[test]
    fn a_blanket_drop_makes_the_narrower_blocks_beneath_it_redundant() {
        let uid = 1000;
        let block = |protocol, ordinal| FlowRule {
            verdict: Verdict::Block,
            precedence: Precedence {
                class: PrecedenceClass::CatchAllBlock,
                ordinal,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol,
            },
            principal: PrincipalScope::User(UserPrincipal::from_linux_uid(uid)),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
            observed_by_program: false,
        };
        let plan = EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(uid),
            flows: vec![block(None, 0), block(Some(L4Proto::Icmp), 1)],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };

        let lowered = lower_plan(&plan, &EgressNames::default());

        assert_eq!(policy_rules(&lowered).len(), 1);
        assert!(policy_rules(&lowered)[0]
            .matches
            .contains(&NftMatch::SkUid(uid)));
    }

    /// The block-all's IPv6 half is an explicit `::/0` drop. On Linux it must
    /// stay an `ip6` match: a family-less drop would also swallow the IPv4
    /// traffic the v4 half exempts.
    #[test]
    fn the_ipv6_half_of_a_block_all_lowers_to_an_ip6_match() {
        let uid = 1000;
        let plan = EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(uid),
            flows: vec![FlowRule {
                verdict: Verdict::Block,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllBlock,
                    ordinal: 0,
                },
                flow: FlowMatch {
                    dst: DstMatch::SubnetV6 {
                        net: std::net::Ipv6Addr::UNSPECIFIED,
                        prefix: 0,
                    },
                    dst_port: None,
                    protocol: None,
                },
                principal: PrincipalScope::User(UserPrincipal::from_linux_uid(uid)),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::ConnectOnly,
                observed_by_program: false,
            }],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };

        let lowered = lower_plan(&plan, &EgressNames::default());

        assert_eq!(policy_rules(&lowered).len(), 1);
        let rule = &policy_rules(&lowered)[0];
        assert!(rule.matches.contains(&NftMatch::DstV6 {
            net: std::net::Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        }));
        assert_eq!(
            rule.verdict,
            NftVerdict::DropReported(DropTag::user(DropKind::Ipv6Cut))
        );
    }

    /// The pruning is per user, and it has to be: one user's blanket drop says
    /// nothing about another's packets, and treating it as if it did would erase
    /// a second user's whole policy.
    #[test]
    fn one_users_blanket_drop_does_not_erase_anothers_rules() {
        let blanket = |uid| EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(uid),
            flows: vec![FlowRule {
                verdict: Verdict::Block,
                precedence: Precedence {
                    class: PrecedenceClass::CatchAllBlock,
                    ordinal: 0,
                },
                flow: FlowMatch {
                    dst: DstMatch::Any,
                    dst_port: None,
                    protocol: None,
                },
                principal: PrincipalScope::User(UserPrincipal::from_linux_uid(uid)),
                app: AppScope::Any,
                egress: EgressConstraint::Any,
                coverage: Coverage::ConnectOnly,
                observed_by_program: false,
            }],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };

        let lowered = lower_plans(&[blanket(1000), blanket(1001)], &EgressNames::default());

        assert_eq!(policy_rules(&lowered).len(), 2);
    }
    /// A pin whose interface is gone keeps its GUARD.
    ///
    /// Dropping both halves is fail-OPEN: the traffic the pin confined to the
    /// tunnel follows the default route instead, at exactly the moment the
    /// tunnel went down. Windows arms a block in the same situation, and the
    /// neutral model's own promise is that removing a pin must not widen it.
    #[test]
    fn an_unresolvable_pin_still_emits_its_leak_guard() {
        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(203, 0, 113, 7)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        // Nothing bound, so the secondary name does not resolve.
        let lowered = lower_flow(&pinned, &EgressNames::default(), &[]);
        assert_eq!(
            lowered.unsupported,
            Some(UnsupportedReason::UnresolvedEgress),
            "the pin itself is still reported unenforceable",
        );
        assert_eq!(
            lowered.rules.len(),
            1,
            "the guard stands: {:?}",
            lowered.rules
        );
        assert_eq!(lowered.rules[0].verdict, pin_drop());
    }

    fn service_pin(ip: Ipv4Addr) -> FlowRule {
        let mut flow = rule(
            PrecedenceClass::KillSwitchPermit,
            0,
            DstMatch::HostV4(ip),
            Verdict::Permit,
        );
        flow.principal = PrincipalScope::ServiceAccounts;
        flow.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        flow
    }

    fn owner_scope() -> ServiceAccountScope {
        ServiceAccountScope {
            owner: Some(UserPrincipal::from_linux_uid(1000)),
            uids: vec![(0, 999), (65534, 65534)],
        }
    }

    /// The owner's service-account pins fold into one accept and one drop over
    /// the service uids, behind the accept for our own marked traffic — three
    /// rules however many addresses, which is the per-packet cost.
    #[test]
    fn the_owners_service_account_pins_lower_to_a_uid_set_behind_our_mark() {
        let plan = plan_of((1..=20).map(|i| service_pin(v4(198, 51, 100, i))).collect());
        let egress = names();
        let lowered = lower_scoped_with(
            &[ScopedPlan {
                plan: &plan,
                egress: &egress,
            }],
            &owner_scope(),
        );
        let rules = &lowered.ruleset.rules;
        assert_eq!(rules.len(), 3, "{rules:?}");
        assert_eq!(rules[0].matches, vec![NftMatch::Mark(OWN_TRAFFIC_MARK)]);
        assert_eq!(rules[0].verdict, NftVerdict::Accept);
        for rule in &rules[1..] {
            assert_eq!(
                rule.matches.first(),
                Some(&NftMatch::SkUidSet(owner_scope().uids)),
                "{rule:?}"
            );
        }
        assert_eq!(rules[1].verdict, NftVerdict::Accept);
        assert_eq!(
            rules[2].verdict,
            NftVerdict::DropReported(DropTag {
                kind: DropKind::Pin,
                system: true,
            })
        );
    }

    /// What the owner's guard blocks for forwarded traffic lands in the forward
    /// chain, silently and with no user condition; no other plan speaks for it.
    #[test]
    fn the_owners_forwarded_blocks_lower_into_the_forward_chain_only() {
        let mut flow = rule(
            PrecedenceClass::KillSwitchBlock,
            0,
            DstMatch::HostV4(v4(203, 0, 113, 5)),
            Verdict::Block,
        );
        flow.principal = PrincipalScope::Forwarded;
        let plan = plan_of(vec![flow]);
        let egress = names();
        let scoped = [ScopedPlan {
            plan: &plan,
            egress: &egress,
        }];
        let lowered = lower_scoped_with(&scoped, &owner_scope());
        assert!(
            lowered.ruleset.rules.is_empty(),
            "{:?}",
            lowered.ruleset.rules
        );
        assert_eq!(lowered.ruleset.forward.len(), 2);
        let reply = &lowered.ruleset.forward[0];
        assert_eq!(
            (reply.matches.as_slice(), reply.verdict),
            (&[NftMatch::CtReply][..], NftVerdict::Accept),
            "replies to an allowed flow come back first"
        );
        let fwd = &lowered.ruleset.forward[1];
        assert_eq!(fwd.verdict, NftVerdict::Drop);
        assert!(
            fwd.matches
                .iter()
                .all(|m| !matches!(m, NftMatch::SkUid(_) | NftMatch::SkUidSet(_))),
            "{fwd:?}"
        );
        let other_owner = ServiceAccountScope {
            owner: Some(UserPrincipal::from_linux_uid(1001)),
            ..owner_scope()
        };
        assert!(lower_scoped_with(&scoped, &other_owner)
            .ruleset
            .forward
            .is_empty());
    }

    /// A forwarded pin is the owner's pair in the forward chain: out the tunnel
    /// accepted, out any other interface dropped, from the same packet on.
    #[test]
    fn a_forwarded_pin_lowers_to_the_tunnel_or_nothing_in_the_forward_chain() {
        let mut flow = rule(
            PrecedenceClass::KillSwitchPermit,
            0,
            DstMatch::HostV4(v4(203, 0, 113, 5)),
            Verdict::Permit,
        );
        flow.principal = PrincipalScope::Forwarded;
        flow.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        let plan = plan_of(vec![flow]);
        let egress = names();
        let scoped = [ScopedPlan {
            plan: &plan,
            egress: &egress,
        }];
        let lowered = lower_scoped_with(&scoped, &owner_scope());
        assert!(
            lowered.ruleset.rules.is_empty(),
            "{:?}",
            lowered.ruleset.rules
        );
        let fwd = &lowered.ruleset.forward[1..];
        assert_eq!(fwd.len(), 2, "{fwd:?}");
        assert_eq!(fwd[0].verdict, NftVerdict::Accept);
        assert!(fwd[0]
            .matches
            .iter()
            .any(|m| matches!(m, NftMatch::OutInterface(_))));
        assert_eq!(fwd[1].verdict, NftVerdict::Drop);
        assert!(!fwd[1]
            .matches
            .iter()
            .any(|m| matches!(m, NftMatch::OutInterface(_))));
    }

    #[test]
    fn service_account_rules_of_a_plan_that_does_not_own_the_table_never_lower() {
        let plan = plan_of(vec![service_pin(v4(198, 51, 100, 1))]);
        let egress = names();
        let scoped = [ScopedPlan {
            plan: &plan,
            egress: &egress,
        }];
        let other_owner = ServiceAccountScope {
            owner: Some(UserPrincipal::from_linux_uid(1001)),
            ..owner_scope()
        };
        for scope in [ServiceAccountScope::default(), other_owner] {
            let lowered = lower_scoped_with(&scoped, &scope);
            assert!(policy_rules(&lowered).is_empty(), "{scope:?}");
        }
        assert!(lower_plan(&plan, &egress).ruleset.rules.is_empty());
    }

    /// The observer learns which rule dropped a packet only from the tag, so
    /// every band has to name itself, and no accept may carry one.
    #[test]
    fn every_drop_is_reported_under_its_bands_kind_and_no_accept_is() {
        let cases = [
            (PrecedenceClass::KillSwitchBlock, DropKind::FailClosed),
            (PrecedenceClass::CatchAllBlock, DropKind::BlockAll),
            (PrecedenceClass::DohBlock, DropKind::DnsLockdown),
            (PrecedenceClass::HardBlock, DropKind::Rule),
            (PrecedenceClass::FakeIpPool, DropKind::RelayPool),
        ];
        for (class, kind) in cases {
            let block = rule(class, 0, DstMatch::HostV4(v4(192, 0, 2, 1)), Verdict::Block);
            let lowered = lower_flow(&block, &names(), &[]);
            assert_eq!(
                lowered.rules[0].verdict,
                NftVerdict::DropReported(DropTag::user(kind)),
                "{class:?}"
            );

            let permit = rule(
                class,
                0,
                DstMatch::HostV4(v4(192, 0, 2, 1)),
                Verdict::Permit,
            );
            let lowered = lower_flow(&permit, &names(), &[]);
            assert_eq!(lowered.rules[0].verdict, NftVerdict::Accept, "{class:?}");
        }
    }

    #[test]
    fn a_whole_family_close_is_reported_as_the_ipv6_cut_not_the_block_all() {
        let v6_all = DstMatch::SubnetV6 {
            net: std::net::Ipv6Addr::UNSPECIFIED,
            prefix: 0,
        };
        let v6_net = DstMatch::SubnetV6 {
            net: "2001:db8::"
                .parse()
                .unwrap_or(std::net::Ipv6Addr::UNSPECIFIED),
            prefix: 32,
        };
        let tag_of = |dst| {
            let block = rule(PrecedenceClass::CatchAllBlock, 0, dst, Verdict::Block);
            lower_flow(&block, &names(), &[]).rules[0].verdict
        };
        assert_eq!(
            tag_of(v6_all),
            NftVerdict::DropReported(DropTag::user(DropKind::Ipv6Cut))
        );
        assert_eq!(
            tag_of(v6_net),
            NftVerdict::DropReported(DropTag::user(DropKind::BlockAll))
        );
    }

    /// root shares uid 0 with the daemon, sshd and the VPN clients: a rule on
    /// uid 0 judges the daemon's DNS forwarding and every SSH reply. So root's
    /// filters never lower, and the accept for our own marked traffic opens
    /// the chain whatever else it holds.
    #[test]
    fn root_is_never_filtered_so_ssh_sessions_and_the_daemons_dns_survive_a_block_all() {
        let root = UserPrincipal::from_linux_uid(0);
        let mut block_all = rule(
            PrecedenceClass::CatchAllBlock,
            0,
            DstMatch::Any,
            Verdict::Block,
        );
        block_all.principal = PrincipalScope::User(root.clone());
        let mut dns = rule(
            PrecedenceClass::CatchAllExempt,
            0,
            DstMatch::Any,
            Verdict::Permit,
        );
        dns.flow.protocol = Some(L4Proto::Udp);
        dns.flow.dst_port = Some(53);
        dns.principal = PrincipalScope::User(root.clone());
        let root_plan = EnforcementPlan {
            principal: root,
            flows: vec![dns, block_all],
            routes: Vec::new(),
            policy_rules: Vec::new(),
        };
        let mut alice = plan_of(vec![rule(
            PrecedenceClass::KillSwitchBlock,
            0,
            DstMatch::HostV4(v4(198, 51, 100, 5)),
            Verdict::Block,
        )]);
        alice.flows[0].principal = PrincipalScope::User(UserPrincipal::from_linux_uid(1000));

        let lowered = lower_plans(&[root_plan, alice], &names());

        assert!(lowered.unsupported.is_empty(), "{:?}", lowered.unsupported);
        let rules = &lowered.ruleset.rules;
        assert!(
            !rules
                .iter()
                .any(|r| r.matches.contains(&NftMatch::SkUid(0))),
            "a rule on uid 0 judges sshd's replies and the daemon's DNS: {rules:?}"
        );
        assert_eq!(rules[0].matches, vec![NftMatch::Mark(OWN_TRAFFIC_MARK)]);
        assert_eq!(rules[0].verdict, NftVerdict::Accept);
        assert_eq!(
            policy_rules(&lowered).len(),
            1,
            "the other user's guard still lowers"
        );
    }

    /// Folding keeps working on reported drops: guards of one band still
    /// become one set, and the set keeps the band's tag.
    #[test]
    fn reported_guards_still_fold_into_one_set() {
        let flows = (1..=10)
            .map(|i| {
                let mut pinned = rule(
                    PrecedenceClass::KillSwitchPermit,
                    i,
                    DstMatch::HostV4(v4(198, 51, 100, i as u8)),
                    Verdict::Permit,
                );
                pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
                pinned
            })
            .collect();
        let lowered = lower_plan(&plan_of(flows), &names());
        let rules = policy_rules(&lowered);
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert_eq!(rules[0].verdict, NftVerdict::Accept);
        assert_eq!(rules[1].verdict, pin_drop());
        assert!(matches!(rules[1].matches[0], NftMatch::DstSetV4(ref set) if set.len() == 10));
    }
}
