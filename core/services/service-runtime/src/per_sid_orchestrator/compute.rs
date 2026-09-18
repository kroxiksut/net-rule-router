//! Shapes and predicates the plan/apply passes share: what a compute
//! produces ([`ComputedFilterSet`], [`SidApplyPreview`]), why it was run
//! ([`ComputeIntent`]), and the small filter-spec classifiers both passes
//! consult.
//!
//! `pub(super)` throughout rather than private: `plan`, `apply` and `builder`
//! are siblings that call into these, not descendants — the visibility widens
//! by exactly one module, which is what the split costs.

use super::*;

/// What SHAPE a fail-closed set takes: cut everything, or only the enumerated
/// destinations. IPv6 is no longer a second switch — a rule host's v6
/// addresses are enumerated alongside its v4 ones and blocked by name.
#[derive(Clone, Copy, Debug)]
pub(super) struct FailClosedPosture {
    pub(super) block_all: bool,
}

/// Filters the orchestrator currently has installed for one SID.
#[derive(Clone, Debug, Default)]
pub struct PerSidFilterSet {
    pub sid: String,
    pub installed: Vec<WfpFilterId>,
    /// Destinations the installed set scopes to. Kept so the NEXT install can
    /// name what just came under enforcement — see
    /// [`PerSidApplyOrchestrator::tear_down_flows_to_new_destinations`].
    pub destinations: Vec<std::net::Ipv4Addr>,
    /// Was the additional adapter resolvable when this set was installed?
    /// Read off the LUID-conditional permits the leak-guard emits only once it
    /// has an adapter; the false → true edge is "the tunnel just came up".
    pub secondary_resolved: bool,
}

/// What applying a candidate rule set to one SID would do — derived without
/// installing anything or moving any live state
/// ([`PerSidApplyOrchestrator::preview_for_sid`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SidApplyPreview {
    pub sid: String,
    /// `false` when this SID would enforce nothing at all (no policy row, or no
    /// rules) — the counts below are then zero by definition, not by luck.
    pub enforceable: bool,
    /// Filters the apply would install.
    pub filters: usize,
    /// Filters currently installed for the SID, so a caller can state the
    /// change rather than the destination.
    pub installed_now: usize,
    /// Filters the apply would ADD — an id-level diff against what is installed,
    /// not a total. An identical policy therefore previews as 0/0, which is what
    /// lets a caller distinguish "nothing to do" from "reinstall everything".
    pub additions: usize,
    /// Filters the apply would REMOVE (installed, absent from the new plan).
    pub removals: usize,
    /// Filter ids that appear more than once in the computed set. Non-empty
    /// means the plan would enforce less than it lists.
    pub colliding_filter_ids: Vec<u64>,
    /// App-rule patterns that matched no executable.
    pub unresolved_apps: Vec<String>,
    /// The SID has a secondary binding the OS could not resolve to an adapter.
    pub secondary_binding_unresolved: bool,
}

/// Result of deriving a SID's WFP filter set from its current policy, rules,
/// and FQDN cache (see [`PerSidApplyOrchestrator::compute_filters_for_sid`]).
/// Split out so the initial [`PerSidApplyOrchestrator::install_for_sid`] and
/// the incremental [`PerSidApplyOrchestrator::reconcile_secondary_coverage`]
/// share exactly one filter-derivation path.
/// Why a filter set is being computed.
///
/// The compute is also where the service publishes what the GUI shows about the
/// CURRENT policy — whether the block-all posture is armed, which app rules
/// resolved to no executable, how many shared IPs the kill-switch spared. A
/// preview that wrote those would make the app describe a policy nobody applied,
/// so the intent travels with the call and every publication is gated on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ComputeIntent {
    /// The result is about to be installed; live status must follow it.
    Apply,
    /// The result is only being inspected (pre-flight, dry run). Nothing about
    /// the live policy may move.
    Preview,
}

impl ComputeIntent {
    /// `true` when this compute owns the live status the GUI reads.
    pub(super) const fn publishes(self) -> bool {
        matches!(self, Self::Apply)
    }
}

pub(super) enum ComputedFilterSet {
    /// The SID installs `filters` (rule-driven Permit/Block + leak-guard),
    /// alongside what the compute learned while deriving them.
    Install(ComputedPlan),
    /// The SID has no per-SID policy row → installs nothing.
    NoPolicy,
    /// The SID has a policy but no active rule revision → installs nothing.
    NoActiveRules,
}

/// What one compute produced: the filter set, plus the facts a caller would
/// otherwise have to re-derive (a pre-flight asks for exactly these).
pub(super) struct ComputedPlan {
    pub(super) filters: Vec<WfpFilterSpec>,
    /// App-rule patterns that matched no executable, so their filters were not
    /// built — the rules are stored but enforce nothing.
    pub(super) unresolved_apps: Vec<String>,
}

/// One compute's BLOCK ids, split by blocking scope — see
/// [`crate::killswitch_drop_registry`] for why the drop detector must keep the
/// bands apart.
pub(super) type KillswitchBlockIds = crate::killswitch_drop_registry::ScopedBlockIds;

/// Fold every BLOCK-action spec's id into `into` — the accumulator behind the
/// reactive VPN-endpoint learner's role-verification registry (see
/// [`PerSidApplyOrchestrator::update_killswitch_registry`]). Permit filters in
/// the same batch (e.g. the kill-switch's own egress-conditional permit half)
/// never qualify — only a BLOCK can be the filter that produced a drop.
/// App-only blocks are additionally recorded as app-scoped.
///
/// A V6 block that names NO destination is the blanket family cut and goes to
/// `ipv6_cut` INSTEAD: role verification exists to prove something about the
/// tunnel, and every consumer of that proof is IPv4-only. Keeping it out also
/// lets the notice path name the real cause instead of blaming a rule. A v6
/// block that DOES name a destination is an ordinary pin — the criterion is the
/// destination, not the layer, or a real v6 pin would be reported as "we closed
/// the family".
pub(super) fn collect_block_ids(specs: &[WfpFilterSpec], into: &mut KillswitchBlockIds) {
    for spec in specs.iter().filter(|s| s.action == WfpAction::Block) {
        if spec.layer.is_v6() && !names_a_destination(spec) {
            into.ipv6_cut.insert(spec.id.raw);
            continue;
        }
        into.all.insert(spec.id.raw);
        if is_app_only_block(spec) {
            into.app_scoped.insert(spec.id.raw);
        }
    }
}

/// True when `spec` is a BLOCK carrying a destination condition — a remote
/// address or subnet. The companion egress-conditional permit of such a block
/// becomes satisfiable as soon as that destination's secondary route exists,
/// which is why installing one must never precede the route (see
/// [`PerSidApplyOrchestrator::with_route_sync`]).
pub(super) fn is_destination_block(spec: &WfpFilterSpec) -> bool {
    spec.action == WfpAction::Block
        && (spec.remote_ip.is_some()
            || !spec.remote_ip_set.is_empty()
            || spec.remote_subnet.is_some()
            || spec.remote_subnet_v6.is_some())
}

/// True when `spec` is a BLOCK that scopes to an application only (an ALE
/// app-id condition) and matches no destination — no remote IP, no remote
/// subnet (v4 or v6), so it is not a catch-all either. Skipping such a block
/// (e.g. its exe did not resolve) cannot uncover a destination, so it must NOT
/// arm the reconcile deferral gate — otherwise a persistently-absent exe
/// defers the superseded-permit delete pass forever.
pub(super) fn is_app_only_block(spec: &WfpFilterSpec) -> bool {
    spec.action == WfpAction::Block
        && spec.app_pattern.is_some()
        && spec.remote_ip.is_none()
        && spec.remote_ip_set.is_empty()
        && spec.remote_subnet.is_none()
        && spec.remote_subnet_v6.is_none()
}

/// Whether a spec carries any destination condition at all.
fn names_a_destination(spec: &WfpFilterSpec) -> bool {
    spec.remote_ip.is_some()
        || !spec.remote_ip_set.is_empty()
        || !spec.remote_ip_set_v6.is_empty()
        || spec.remote_subnet.is_some()
        || spec.remote_subnet_v6.is_some()
}

/// The IPv4 half of a mixed-family address list, in order.
///
/// Named at every call site that narrows, so the places still waiting for the
/// other family are a grep away rather than an implicit `match`.
pub(crate) fn only_v4_of(ips: &[std::net::IpAddr]) -> Vec<std::net::Ipv4Addr> {
    ips.iter()
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

/// Whether `ip` sits in any of `subnets`, given as `(network, prefix_len)`.
pub(super) fn in_any_subnet(ip: std::net::Ipv4Addr, subnets: &[(std::net::Ipv4Addr, u8)]) -> bool {
    let addr = u32::from(ip);
    subnets.iter().any(|(net, prefix)| {
        if *prefix == 0 {
            return true;
        }
        if *prefix > 32 {
            return false;
        }
        let mask = u32::MAX << (32 - u32::from(*prefix));
        (addr & mask) == (u32::from(*net) & mask)
    })
}

/// Choose the behaviour mode the codegen sees for a SID. The per-SID
/// policy's `mode` always wins over the active revision's default —
/// individual users can opt into `StrictSecondaryFailClosed` even on a
/// `PreferPrimary` default profile.
pub(super) fn behavior_mode_for_codegen(
    policy: &PerSidPolicySnapshot,
    _revision_default: RouteBehaviorMode,
) -> RouteBehaviorMode {
    // The two enums share variant names — keep the mapping by hand
    // so a future divergence (extra variant on one side) becomes a
    // compile error.
    match policy.mode {
        PerSidBehaviorMode::PreferPrimary => RouteBehaviorMode::PreferPrimary,
        PerSidBehaviorMode::PreferSecondaryWhenAvailable => {
            RouteBehaviorMode::PreferSecondaryWhenAvailable
        }
        PerSidBehaviorMode::StrictSecondaryFailClosed => {
            RouteBehaviorMode::StrictSecondaryFailClosed
        }
    }
}
