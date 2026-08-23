//! The Linux [`PolicyEnforcer`]: every active user's plan onto one ruleset.
//!
//! Sits above [`crate::nft_backend`] and holds the two things the neutral
//! service cannot: which adapters each principal bound, and what those bindings
//! resolve to on the machine RIGHT NOW.
//!
//! ## Why one pass, never one apply per user
//!
//! Applying our table replaces its whole contents, so looping per user would
//! leave only the last one enforced. Their rules interleave safely because each
//! carries `meta skuid` — a rule scoped to one uid cannot match another user's
//! packet, whatever order it sits in.
//!
//! ## Why resolution happens here, per pass
//!
//! A binding is a name the user saw; the link behind it can go down, be renamed
//! or come back different. Resolving on every pass means a rule whose interface
//! is gone is reported unenforced rather than applied without its pin — which is
//! exactly the moment a pin exists for.

#![cfg(target_os = "linux")]

use std::sync::Arc;

use nrr_platform_api::adapters::AdapterEventSource;
use nrr_platform_api::enforcement::{
    ApplyReport, ChannelAvailability, EgressBindingSource, EnforcementFailure, EnforcementPlan,
    PolicyEnforcer, UserPrincipal,
};

use crate::lower_linux::{lower_scoped, EgressNames, ScopedPlan};
use crate::nft_apply::NftCliEnforcement;

pub struct NftPolicyEnforcer {
    bindings: Arc<dyn EgressBindingSource>,
    adapters: Arc<dyn AdapterEventSource>,
    cli: NftCliEnforcement,
    /// Asks a layer above whether the additional link is actually carrying
    /// traffic, by interface index. A link can be `Up` with an address and still
    /// be a tunnel whose far end is gone — the state of the interface says
    /// nothing about the path behind it.
    ///
    /// A callback rather than the tracker itself: the hysteresis, the baseline
    /// requirement and the evidence-freshness rules are policy and live in the
    /// neutral layer, which this crate must not depend on.
    liveness: Option<LivenessOracle>,
}

/// `false` = this interface has been declared dead. Anything else — alive,
/// unprobeable, feature off — is `true`, because the only safe direction for an
/// indeterminate answer is "still usable".
pub type LivenessOracle = Arc<dyn Fn(u32) -> bool + Send + Sync>;

impl NftPolicyEnforcer {
    pub fn new(
        bindings: Arc<dyn EgressBindingSource>,
        adapters: Arc<dyn AdapterEventSource>,
    ) -> Self {
        Self {
            bindings,
            adapters,
            cli: NftCliEnforcement::new(),
            liveness: None,
        }
    }

    /// Consult `oracle` about the additional link before calling it available.
    /// Builder-style: without it the enforcer trusts the interface state alone,
    /// which is what it did before any probe existed.
    #[must_use]
    pub fn with_liveness(mut self, oracle: LivenessOracle) -> Self {
        self.liveness = Some(oracle);
        self
    }

    /// Whether the host can enforce at all — asked once at start so a missing
    /// `nftables` package is a clear refusal rather than a failure on the first
    /// rule the user expects to be applied.
    pub fn probe(&self) -> Result<(), EnforcementFailure> {
        self.cli
            .probe()
            .map_err(|e| EnforcementFailure::new(e.to_string()))
    }
}

impl NftPolicyEnforcer {
    /// Resolve one principal's bindings against the links present now.
    fn resolve(
        &self,
        principal: &UserPrincipal,
        adapters: &[nrr_platform_api::adapters::AdapterInfo],
    ) -> EgressNames {
        let binding = self.bindings.bindings_for(principal);
        EgressNames::resolve_from_adapters(
            adapters,
            binding.primary.as_deref(),
            binding.secondary.as_deref(),
        )
    }
}

impl PolicyEnforcer for NftPolicyEnforcer {
    fn enforce(&self, plans: &[EnforcementPlan]) -> Result<ApplyReport, EnforcementFailure> {
        // Read the links ONCE for the pass: every plan is resolved against the
        // same snapshot, so two users cannot be enforced against two different
        // states of the machine.
        let adapters = self
            .adapters
            .enumerate_all()
            .map_err(|e| EnforcementFailure::new(format!("adapters could not be read: {e}")))?;

        let resolved: Vec<EgressNames> = plans
            .iter()
            .map(|plan| self.resolve(&plan.principal, &adapters))
            .collect();

        let scoped: Vec<ScopedPlan<'_>> = plans
            .iter()
            .zip(resolved.iter())
            .map(|(plan, egress)| ScopedPlan { plan, egress })
            .collect();

        let lowered = lower_scoped(&scoped);
        let applied = lowered.ruleset.rules.len();
        self.cli
            .apply(&lowered.ruleset)
            .map_err(|e| EnforcementFailure::new(e.to_string()))?;

        Ok(ApplyReport {
            applied,
            skipped: lowered.unsupported.len(),
            failed: 0,
            notes: lowered
                .unsupported
                .iter()
                .map(crate::nft_backend::note_for)
                .collect(),
        })
    }

    fn channel_availability(&self, principal: &UserPrincipal) -> ChannelAvailability {
        // A read failure reports both channels down. That is the safe reading:
        // the caller's fail-closed branch blocks rather than routes, and
        // claiming a link is up when we could not look is how traffic leaves
        // over the wrong one.
        let Ok(adapters) = self.adapters.enumerate_all() else {
            return ChannelAvailability::default();
        };
        let names = self.resolve(principal, &adapters);
        // A resolved name is necessary but not sufficient for the additional
        // link: a tunnel whose peer stopped answering still presents an `Up`
        // interface with an address, and routing traffic into it is a silent
        // black hole rather than a leak the user can see.
        let secondary_alive = names.secondary.as_ref().is_some_and(|name| {
            let Some(oracle) = self.liveness.as_ref() else {
                return true;
            };
            adapters
                .iter()
                .find(|a| &a.friendly_name == name || &a.adapter_name == name)
                .is_none_or(|adapter| oracle(adapter.index))
        });
        ChannelAvailability {
            primary: names.primary.is_some(),
            secondary: secondary_alive,
        }
    }

    fn teardown(&self) -> Result<(), EnforcementFailure> {
        self.cli
            .teardown(crate::lower_linux::NRR_TABLE)
            .map_err(|e| EnforcementFailure::new(e.to_string()))
    }
}
