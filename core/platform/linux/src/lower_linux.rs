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
    PrincipalScope, Verdict,
};

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
    let mut indexed: Vec<(usize, &FlowRule)> = plan.flows.iter().enumerate().collect();
    // Higher rank first; ties broken by the planner's ordinal, then by original
    // position so the output is stable for identical input (re-apply must be a
    // no-op, and a churning ruleset would defeat that).
    indexed.sort_by(|(ai, a), (bi, b)| {
        b.precedence
            .class
            .rank()
            .cmp(&a.precedence.class.rank())
            .then(a.precedence.ordinal.cmp(&b.precedence.ordinal))
            .then(ai.cmp(bi))
    });

    let mut rules = Vec::new();
    let mut unsupported = Vec::new();

    for (index, flow) in indexed {
        match lower_flow(flow, egress) {
            Ok(lowered) => rules.extend(lowered),
            Err(reason) => unsupported.push(UnsupportedRule { index, reason }),
        }
    }

    LoweredPlan {
        ruleset: NftRuleset {
            family: NftFamily::Inet,
            table: NRR_TABLE.to_owned(),
            chain: NRR_CHAIN.to_owned(),
            rules,
        },
        unsupported,
    }
}

/// Lower one rule. An `OnlyVia` pin becomes TWO rules — accept when leaving the
/// pinned interface, drop otherwise — which is the leak-proof shape: the drop
/// is scoped to the same destination, so nothing else is affected.
fn lower_flow(flow: &FlowRule, egress: &EgressNames) -> Result<Vec<NftRule>, UnsupportedReason> {
    if let AppScope::Program { key, .. } = &flow.app {
        return Err(UnsupportedReason::AppScoped { key: key.clone() });
    }

    let mut base = Vec::new();
    if let PrincipalScope(Some(principal)) = &flow.principal {
        // Per-user matching is a plain condition here — the capability Windows
        // has to emulate with per-SID filter sets.
        if let Some(uid) = principal.as_unix_uid() {
            base.push(NftMatch::SkUid(uid));
        }
    }
    base.extend(lower_flow_match(&flow.flow));

    let comment = rule_comment(flow);

    match &flow.egress {
        EgressConstraint::Any => Ok(vec![NftRule {
            matches: base,
            verdict: verdict_of(flow.verdict),
            comment,
        }]),
        EgressConstraint::OnlyVia(reference) => {
            let device = egress
                .resolve(reference)
                .ok_or(UnsupportedReason::UnresolvedEgress)?;
            let mut pinned = base.clone();
            pinned.push(NftMatch::OutInterface(device));
            Ok(vec![
                NftRule {
                    matches: pinned,
                    verdict: NftVerdict::Accept,
                    comment: format!("{comment} via"),
                },
                // Same destination, any other interface: dropped. Without this
                // the pin would be advice — traffic would simply follow the
                // default route when the pinned link is down, which is the leak
                // the pin exists to prevent.
                NftRule {
                    matches: base,
                    verdict: NftVerdict::Drop,
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

const fn verdict_of(verdict: Verdict) -> NftVerdict {
    match verdict {
        Verdict::Permit => NftVerdict::Accept,
        Verdict::Block => NftVerdict::Drop,
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
        P::DefaultCatchAll => "default",
        P::RouteRule(RouteRole::Primary) => "route-primary",
        P::RouteRule(RouteRole::Secondary) => "route-secondary",
        P::DohBlock => "doh-block",
        P::CatchAllBlock => "catch-all-block",
        P::CatchAllExempt => "catch-all-exempt",
        P::KillSwitchBlock => "kill-switch-block",
        P::KillSwitchPermit => "kill-switch-permit",
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
            principal: PrincipalScope(None),
            app: AppScope::Any,
            egress: EgressConstraint::Any,
            coverage: Coverage::ConnectOnly,
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

    fn names() -> EgressNames {
        EgressNames {
            primary: Some("eth0".into()),
            secondary: Some("tun0".into()),
        }
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
                DstMatch::HostV4(v4(1, 1, 1, 1)),
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
        let bands: Vec<&str> = lowered
            .ruleset
            .rules
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
                DstMatch::HostV4(v4(3, 3, 3, 3)),
                Verdict::Permit,
            ),
            rule(
                PrecedenceClass::RouteRule(RouteRole::Secondary),
                0,
                DstMatch::HostV4(v4(1, 1, 1, 1)),
                Verdict::Permit,
            ),
            rule(
                PrecedenceClass::RouteRule(RouteRole::Secondary),
                1,
                DstMatch::HostV4(v4(2, 2, 2, 2)),
                Verdict::Permit,
            ),
        ]);

        let lowered = lower_plan(&plan, &names());
        let comments: Vec<&str> = lowered
            .ruleset
            .rules
            .iter()
            .map(|r| r.comment.as_str())
            .collect();
        assert_eq!(
            comments,
            vec![
                "route-secondary#0",
                "route-secondary#1",
                "route-secondary#2"
            ],
        );
    }

    /// A pin that only accepts on the right interface is advice, not a pin:
    /// when the tunnel drops, traffic would follow the default route. The
    /// scoped drop is what makes it leak-proof.
    #[test]
    fn an_egress_pin_lowers_to_accept_on_the_link_plus_a_scoped_drop() {
        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(93, 184, 216, 34)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let lowered = lower_plan(&plan_of(vec![pinned]), &names());
        assert_eq!(lowered.ruleset.rules.len(), 2);

        let accept = &lowered.ruleset.rules[0];
        assert_eq!(accept.verdict, NftVerdict::Accept);
        assert!(accept
            .matches
            .contains(&NftMatch::OutInterface("tun0".into())));

        let guard = &lowered.ruleset.rules[1];
        assert_eq!(guard.verdict, NftVerdict::Drop);
        assert!(
            !guard
                .matches
                .iter()
                .any(|m| matches!(m, NftMatch::OutInterface(_))),
            "the drop must not be tied to an interface, or it guards nothing",
        );
        // Same destination on both — the drop is scoped, not a blanket cut.
        assert!(guard.matches.contains(&NftMatch::DstV4 {
            net: v4(93, 184, 216, 34),
            prefix: 32,
        }));
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
            key: "telegram".into(),
            exe_paths: vec!["C:/telegram.exe".into()],
        };

        let lowered = lower_plan(&plan_of(vec![app_rule]), &names());
        assert!(lowered.ruleset.rules.is_empty());
        assert_eq!(
            lowered.unsupported,
            vec![UnsupportedRule {
                index: 0,
                reason: UnsupportedReason::AppScoped {
                    key: "telegram".into()
                },
            }],
        );
    }

    /// An unresolvable pin must not silently become an unpinned accept — that
    /// would route the very traffic the pin exists to contain over the wrong
    /// link.
    #[test]
    fn a_pin_to_an_absent_adapter_is_unsupported_never_an_unpinned_accept() {
        let mut pinned = rule(
            PrecedenceClass::RouteRule(RouteRole::Secondary),
            0,
            DstMatch::HostV4(v4(9, 9, 9, 9)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);

        let absent = EgressNames {
            primary: Some("eth0".into()),
            secondary: None,
        };
        let lowered = lower_plan(&plan_of(vec![pinned]), &absent);
        assert!(lowered.ruleset.rules.is_empty());
        assert_eq!(
            lowered.unsupported,
            vec![UnsupportedRule {
                index: 0,
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
            DstMatch::HostV4(v4(9, 9, 9, 9)),
            Verdict::Permit,
        );
        pinned.egress = EgressConstraint::OnlyVia(EgressRef::Secondary);
        let lowered = lower_plan(&plan_of(vec![pinned]), &names);
        assert!(lowered.ruleset.rules.is_empty());
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
            DstMatch::HostV4(v4(8, 8, 8, 8)),
            Verdict::Permit,
        );
        scoped.principal = PrincipalScope(Some(UserPrincipal::from_linux_uid(1001)));

        let lowered = lower_plan(&plan_of(vec![scoped]), &names());
        assert!(lowered.ruleset.rules[0]
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
        let matches = &lowered.ruleset.rules[0].matches;
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
                DstMatch::HostV4(v4(5, 5, 5, 5)),
                Verdict::Block,
            ),
            rule(
                PrecedenceClass::KillSwitchBlock,
                0,
                DstMatch::HostV4(v4(6, 6, 6, 6)),
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
}
