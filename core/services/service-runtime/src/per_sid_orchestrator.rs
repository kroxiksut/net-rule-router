//! per-SID apply orchestrator.
//!
//! Bridges three subsystems:
//! - [`crate::active_sid_registry::ActiveSidRegistry`] tells
//!   the orchestrator which SIDs currently have a live IPC connection.
//! - `RouteBindingsRepository` carries the per-SID `route_bindings` /
//!   `behavior_mode` / `secondary_block_policy` rows.
//!   The orchestrator reads through a [`RoutePolicySource`] trait so
//!   tests can inject scripted snapshots.
//! - [`nrr_platform_api::wfp::WfpSession`] installs the WFP filters
//!   that actually shape per-user routing, carrying `user_sid` per filter.
//!
//! ## Lifecycle
//!
//! On every active-set transition published by `ActiveSidRegistry`:
//! - **SID enters** → `install_for_sid` reads the user's policy
//!   snapshot, generates per-user [`WfpFilterSpec`] entries (each
//!   carrying `user_sid = Some(sid)`), runs them through the WFP
//!   session, and records the installed filter IDs in
//!   [`PerSidFilterSet`].
//! - **SID exits** → `remove_for_sid` looks up the installed filter
//!   IDs, issues `DeleteFilter` actions for each, and drops the entry.
//!
//! When a user's policy changes mid-session (`RoutePolicyUpdate` IPC
//! handler), the orchestrator's [`PerSidApplyOrchestrator::recompile_for_sid`]
//! does a full remove-then-install pass for that SID. Diff-based recompile
//! (only changed filters) is a future optimisation once the rules schema
//! settles.
//!
//! ## No user logged in, and the admin baseline
//!
//! Enforcement follows **tray presence**: filters exist only for SIDs in
//! the active set. When **nobody is logged in** the active set is empty,
//! so `reconcile` installs nothing and routing is **passthrough** (system
//! default).
//!
//! The admin **baseline** is a per-user *default*, not a machine-wide
//! floor: it reaches the wire only as a per-user read-through — a real
//! `S-…` SID whose own revision is absent resolves
//! the baseline at install time (`RulesProvider::active_rules_for`). The
//! baseline principal is therefore **never** a routable per-SID target of
//! its own; `install_for_sid` refuses the sentinel
//! ([`OrchestratorError::BaselineNotRoutable`]). Consequence: with no
//! logged-in user there is no baseline enforcement on the wire — by
//! design, so the service never shapes pre-login / system traffic.
//!
//! ## Decision runner — current scope
//!
//! `PerSidDecisionRunner::build_filter_specs` translates a
//! [`PerSidPolicySnapshot`] into a small fixed set of WFP specs that
//! demonstrates the wire-up:
//! - One `Permit` filter at `AleAuthConnectV4` with `user_sid = sid`
//!   for each bound role (primary / secondary).
//!
//! Rules reach enforcement through the codegen path, not through a
//! per-connection engine call: the orchestrator turns the rule book into
//! filter specs. The placeholder set here proves:
//! - filter-set lifecycle (install / remove / replace),
//! - per-SID isolation via `FWPM_CONDITION_ALE_USER_ID`,
//! - audit and registry coordination.
//!
//! ## Out of scope here
//!
//! - Decision-engine rule iteration.
//! - Diff-based recompile — performance optimisation; current
//!   implementation is full replace.
//! - WFP filter weight ordering across SIDs — current impl puts every
//!   per-SID filter at the same `BASE_WEIGHT`; production may need a
//!   weight map keyed by (SID, role).
//!
//! ## Module map
//!
//! Entry point only: imports + re-exports. `types` holds the domain/audit
//! data shapes and [`OrchestratorError`]; `compute` holds what a filter
//! compute produces and the predicates `plan`/`apply` classify specs with;
//! `state` holds [`PerSidApplyOrchestrator`] itself; `builder` constructs
//! it; `plan` derives a SID's filter set; `apply` installs/reconciles/removes
//! it; `posture` holds the posture-log latch and per-SID notification
//! helpers; `shadow_compare` (Windows only) runs the neutral-plan parity
//! check; `registry_wiring` wires the orchestrator to the active-SID
//! registry and the policy-apply trigger.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nrr_domain::canonical::CanonicalRuleBook;
use nrr_platform_api::types::{WfpAction, WfpFilterAction, WfpFilterId, WfpFilterSpec};
use nrr_platform_api::wfp::{FilterFailureMode, WfpSession};
use nrr_shared::RouteBehaviorMode;

use crate::active_sid_registry::ActiveSidRegistry;
use crate::app_observation_lookup::{AppObservationLookup, AppObservationStore};
use crate::fqdn_cache_lookup::FqdnCacheLookup;
use crate::killswitch_codegen::{FailClosedExemptions, KillSwitchResolution};
use crate::wfp_codegen::{generate_filters, CodegenInput};

mod types;
pub use types::{
    ActiveRulesSnapshot, NoopPerSidApplyAudit, NoopRulesProvider, OrchestratorError,
    PerSidApplyAudit, PerSidApplyAuditKind, PerSidApplyAuditRecord, PerSidBehaviorMode,
    PerSidBinding, PerSidPolicySnapshot, RoutePolicySource, RulesProvider,
};

mod compute;
use compute::*;
pub use compute::{PerSidFilterSet, SidApplyPreview};

mod state;
use state::*;
pub use state::{
    FailClosedExemptionsResolver, FakeIpContextProvider, FilterFailureModeSource,
    Ipv6GuardResolver, KillSwitchResolver, PerSidApplyOrchestrator, RouteSyncHook,
    UnresolvedHostsSink, VpnClientAppsProvider,
};

mod posture;
use posture::*;

#[cfg(windows)]
mod shadow_compare;

mod registry_wiring;
pub use registry_wiring::{
    wire_orchestrator_to_registry, FallbackRoutingSidFn, OrchestratorRoutePolicyApplyTrigger,
    TriggerPausedCheckFn,
};

mod apply;
mod builder;
mod plan;
#[cfg(test)]
mod tests;
