//! The Linux [`EnforcementBackend`]: plan in, kernel state out.
//!
//! Three pieces already exist separately — `lower_linux` (pure), `nft_apply`
//! (render + `nft`), and the neutral trait. This joins them and is deliberately
//! thin: everything worth testing lives on either side of it.
//!
//! ## Egress names are supplied per reconcile, never cached
//!
//! A plan names egress neutrally (`Primary` / `Secondary`); the interface name
//! is resolved by the caller and handed in on every call. That mirrors the rule
//! the Windows side follows with LUIDs: a link that reconnects comes back with
//! a different identity, and a cached one would pin traffic to an interface
//! that no longer exists — silently, because the rule would still look applied.

use nrr_platform_api::enforcement::{
    ApplyReport, EnforcementBackend, EnforcementCapabilities, EnforcementPlan,
};

use crate::lower_linux::{lower_plan, EgressNames, UnsupportedReason};
use crate::nft_apply::{NftApplyError, NftCliEnforcement};

/// Enforces a plan with nftables, driving `nft` as the mechanism.
#[derive(Debug, Clone, Default)]
pub struct NftablesEnforcement {
    egress: EgressNames,
    cli: NftCliEnforcement,
}

impl NftablesEnforcement {
    /// Build a backend that resolves neutral egress references with `egress`.
    /// Construct it per reconcile from freshly-read adapter facts.
    pub fn new(egress: EgressNames) -> Self {
        Self {
            egress,
            cli: NftCliEnforcement::new(),
        }
    }

    /// Whether the host can enforce at all. Called once at daemon start so a
    /// missing `nftables` package is a clear refusal up front, instead of a
    /// failure on the first rule the user expects to be applied.
    pub fn probe(&self) -> Result<(), NftApplyError> {
        self.cli.probe()
    }

    /// Remove every rule this product installed, and nothing else.
    pub fn teardown(&self) -> Result<(), NftApplyError> {
        self.cli.teardown(crate::lower_linux::NRR_TABLE)
    }
}

impl EnforcementBackend for NftablesEnforcement {
    type Error = NftApplyError;

    fn reconcile(&self, plan: &EnforcementPlan) -> Result<ApplyReport, Self::Error> {
        let lowered = lower_plan(plan, &self.egress);
        let applied = lowered.ruleset.rules.len();

        self.cli.apply(&lowered.ruleset)?;

        // What could not be expressed is REPORTED, never dropped in silence: a
        // backend that quietly enforces less than it was given is
        // indistinguishable from one that enforces all of it.
        let mut notes = Vec::new();
        for rule in &lowered.unsupported {
            notes.push(match &rule.reason {
                UnsupportedReason::AppScoped { key } => format!(
                    "rule {} is scoped to application `{key}`: nftables has no per-executable \
                     match, so it is enforced through observed destinations instead",
                    rule.index
                ),
                UnsupportedReason::UnresolvedEgress => format!(
                    "rule {} pins egress to an adapter that is not present right now; \
                     it was NOT applied, so the pinned traffic is not routed by it",
                    rule.index
                ),
            });
        }

        Ok(ApplyReport {
            applied,
            skipped: lowered.unsupported.len(),
            failed: 0,
            notes,
        })
    }

    fn capabilities(&self) -> EnforcementCapabilities {
        EnforcementCapabilities::linux_mvp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nrr_platform_api::enforcement::{
        AppScope, Coverage, DstMatch, EgressConstraint, EgressRef, FlowMatch, FlowRule, Precedence,
        PrecedenceClass, PrincipalScope, UserPrincipal, Verdict,
    };
    use nrr_shared::RouteRole;

    fn plan_with(flows: Vec<FlowRule>) -> EnforcementPlan {
        EnforcementPlan {
            principal: UserPrincipal::from_linux_uid(1000),
            flows,
            routes: Vec::new(),
            policy_rules: Vec::new(),
        }
    }

    fn app_rule() -> FlowRule {
        FlowRule {
            verdict: Verdict::Permit,
            precedence: Precedence {
                class: PrecedenceClass::RouteRule(RouteRole::Secondary),
                ordinal: 0,
            },
            flow: FlowMatch {
                dst: DstMatch::Any,
                dst_port: None,
                protocol: None,
            },
            principal: PrincipalScope(None),
            app: AppScope::Program {
                key: "telegram".into(),
                exe_paths: Vec::new(),
            },
            egress: EgressConstraint::OnlyVia(EgressRef::Secondary),
            coverage: Coverage::ConnectOnly,
        }
    }

    /// The capability set is the declared contract the GUI degrades against, so
    /// it must state the real inversions rather than flatter the platform.
    #[test]
    fn capabilities_admit_that_per_app_blocking_can_leak_here() {
        let caps = NftablesEnforcement::default().capabilities();
        assert!(caps.per_user_routing, "per-user routing is a Linux win");
        assert!(caps.per_user_all_protocol_scoping);
        assert!(
            !caps.per_app_block_leakproof,
            "without the eBPF connect-verdict an app block CAN leak; saying otherwise \
             would let the GUI promise a guarantee the mechanism does not provide",
        );
    }

    /// Reconcile builds the ruleset before it touches the host, so the
    /// unsupported list is decided by lowering — assert it on the lowering the
    /// backend would use, with no kernel involved.
    #[test]
    fn an_app_scoped_rule_is_surfaced_as_a_note_not_swallowed() {
        let backend = NftablesEnforcement::new(EgressNames {
            primary: Some("eth0".into()),
            secondary: Some("tun0".into()),
        });
        let lowered = lower_plan(&plan_with(vec![app_rule()]), &backend.egress);
        assert_eq!(lowered.unsupported.len(), 1);
        assert!(lowered.ruleset.rules.is_empty());
    }
}
