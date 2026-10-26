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
/// destinations (a rule host's v6 addresses among them, blocked by name).
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
    pub destinations: Vec<std::net::IpAddr>,
    /// Was the additional adapter resolvable when this set was installed?
    /// Read off the LUID-conditional permits the leak-guard emits only once it
    /// has an adapter; the false → true edge is "the tunnel just came up".
    pub secondary_resolved: bool,
    /// Rule networks the installed set scopes to, compared like
    /// [`Self::destinations`] to name what just came under enforcement.
    pub networks: Vec<nrr_shared::ip_block::IpBlock>,
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

/// The BLOCK ids of the rule codegen's own output: every one is a deny rule
/// the user wrote, since the codegen emits Block for nothing else.
pub(super) fn rule_block_ids(specs: &[WfpFilterSpec]) -> HashSet<u64> {
    specs
        .iter()
        .filter(|s| s.action == WfpAction::Block)
        .map(|s| s.id.raw)
        .collect()
}

/// [`collect_block_ids`] for the service-account twins: role-verifying like the
/// owner's (a tunnel client's drop still teaches its endpoint), and marked so
/// every other drop observer can leave them out.
pub(super) fn collect_service_account_block_ids(
    specs: &[WfpFilterSpec],
    into: &mut KillswitchBlockIds,
) {
    collect_block_ids(specs, into);
    into.service_accounts.extend(
        specs
            .iter()
            .filter(|s| s.action == WfpAction::Block)
            .map(|s| s.id.raw),
    );
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
            || spec.remote_subnet_v6.is_some()
            || !spec.remote_subnet_set.is_empty())
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
        && spec.remote_subnet_set.is_empty()
}

/// Whether a spec carries any destination condition at all.
fn names_a_destination(spec: &WfpFilterSpec) -> bool {
    spec.remote_ip.is_some()
        || !spec.remote_ip_set.is_empty()
        || !spec.remote_ip_set_v6.is_empty()
        || spec.remote_subnet.is_some()
        || spec.remote_subnet_v6.is_some()
        || !spec.remote_subnet_set.is_empty()
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

/// The behaviour mode a principal is planned under, on every OS: the per-user
/// policy's `mode`. The rules snapshot carries only a placeholder default, so
/// a planner that reads the mode from there plans everyone as prefer-main.
pub(crate) fn behavior_mode_for_codegen(policy: &PerSidPolicySnapshot) -> RouteBehaviorMode {
    behavior_mode_of_snapshot(policy)
}

/// Whether the level in force is "everything": a stored "routed sites" under
/// the additional default route means it too.
pub(crate) fn protects_everything(policy: &PerSidPolicySnapshot) -> bool {
    policy
        .leak_protection
        .effective(behavior_mode_of_snapshot(policy))
        == nrr_domain::LeakProtection::Everything
}

/// `principal`'s mode from its stored policy; a principal with no policy row
/// never bound their links and is read as prefer-main, the GUI's default.
pub fn behavior_mode_of(
    policy: &dyn crate::per_sid_orchestrator::RoutePolicySource,
    principal: &str,
) -> RouteBehaviorMode {
    policy
        .load_for_sid(principal)
        .map(|snapshot| behavior_mode_of_snapshot(&snapshot))
        .unwrap_or(RouteBehaviorMode::PreferPrimary)
}

fn behavior_mode_of_snapshot(policy: &PerSidPolicySnapshot) -> RouteBehaviorMode {
    // The two enums share variant names — keep the mapping by hand
    // so a future divergence (extra variant on one side) becomes a
    // compile error.
    match policy.mode {
        PerSidBehaviorMode::PreferPrimary => RouteBehaviorMode::PreferPrimary,
        PerSidBehaviorMode::PreferSecondaryWhenAvailable => {
            RouteBehaviorMode::PreferSecondaryWhenAvailable
        }
    }
}
