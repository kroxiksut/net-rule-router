//! Service health / state aggregator and observable snapshot.
//!
//! The `HealthAggregator` collects per-component severities (storage,
//! policy, diagnostics, IPC, apply, adapter availability) and rolls
//! them up into a single `ServiceRuntimeState` plus a public
//! `ServiceSnapshot` DTO that the IPC layer hands back to
//! the GUI/tray on `service.health.get` and `snapshot.initial.get`.
//!
//! ## What this module is *not*
//!
//! - It is **not** the source of truth for policy mutation. Decisions
//!   about whether to apply a candidate revision live in the policy
//!   layer and apply controller. The health
//!   aggregator only *observes* state.
//! - It does **not** perform I/O. Components push their statuses via
//!   `record_*` methods; the aggregator stores them and computes the
//!   roll-up on read.
//!
//! ## Snapshot freshness
//!
//! Each component carries `updated_at` (epoch seconds). The aggregator
//! also tracks `snapshot_refreshed_at` for cache-driven reads, hooked to
//! the runtime loop's tick. For the GUI
//! polling path the snapshot is recomputed on every `service.health.get`
//! since composition is in-memory and cheap (O(N) over <10 components).
//!
//! ## Severity aggregation
//!
//! `worst_severity = max(component.severity for component in components)`
//! using the `Ord` impl on `ServiceHealthSeverity`:
//! `Ok < Warning < Degraded < Blocking < Unknown`. The state machine
//! mapping:
//!
//! | Worst severity | `ServiceRuntimeState`           |
//! |----------------|--------------------------------|
//! | Ok / Warning   | `Running`                      |
//! | Degraded       | `Degraded`                     |
//! | Blocking       | `RecoveryRequired`             |
//! | Unknown        | `Starting` (still bootstrapping)|
//!
//! Caller can override with `mark_starting()` / `mark_stopping()` /
//! `mark_disabled()` so SCM lifecycle transitions take precedence over
//! the component-derived state.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::managers::{BootstrapReport, HealthReporter};
use crate::policy_loader::PolicyLoadResult;
use crate::state::{
    ActiveRevisionState, ServiceHealthSeverity, ServicePolicyState, ServiceRuntimeState,
};

// ── Component identity ───────────────────────────────────────────────────────

/// Stable slugs for the components the aggregator tracks. New
/// components (e.g. a runtime-loop watchdog or apply controller)
/// should add a new variant here so the
/// snapshot keeps a fixed shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum HealthComponent {
    /// `nrr-storage` state DB + cache DB.
    Storage,
    /// Active revision / LKG state machine.
    Policy,
    /// `nrr-diagnostics` audit writer + log writer.
    Diagnostics,
    /// IPC server. Down-state means GUI cannot reach the
    /// service at all; mutation operations are blocked.
    Ipc,
    /// Apply controller. Down-state means policy cannot
    /// be pushed to Windows routing.
    Apply,
    /// Adapter availability / external connectivity.
    Adapters,
}

impl HealthComponent {
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Policy => "policy",
            Self::Diagnostics => "diagnostics",
            Self::Ipc => "ipc",
            Self::Apply => "apply",
            Self::Adapters => "adapters",
        }
    }
}

// ── Snapshot DTOs ────────────────────────────────────────────────────────────

/// Single component's status as published in the snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthComponentSnapshot {
    pub component: HealthComponent,
    pub severity: ServiceHealthSeverity,
    /// Operator-grade English message describing the current state.
    pub message: String,
    /// Epoch-seconds timestamp for the last `record_*` call. Lets the
    /// GUI surface a "stale" badge when no update arrived in a
    /// configurable window.
    pub updated_at_epoch_secs: u64,
}

/// Read-only top-level snapshot returned through the IPC
/// `service.health.get` operation. Pinned to a flat shape so the wire
/// DTO stays predictable across blocks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceSnapshot {
    /// Aggregated runtime state. Honours SCM-lifecycle overrides
    /// (`Starting`, `Stopping`, `Disabled`) when set explicitly.
    pub state: ServiceRuntimeState,
    /// Worst severity across all known components. Drives the GUI's
    /// "service is healthy / degraded / needs attention" indicator.
    pub worst_severity: ServiceHealthSeverity,
    /// Per-component breakdown. Sorted by component slug for stable
    /// comparison across snapshots.
    pub components: Vec<HealthComponentSnapshot>,
    /// Currently-loaded revision summary, when available. Mirrors the
    /// last `record_policy` outcome.
    pub current_revision: Option<ActiveRevisionState>,
    /// Logical state of the policy state machine.
    pub policy_state: ServicePolicyState,
    /// Timestamp when the aggregator last recomputed the snapshot
    /// (i.e. the moment `snapshot()` was called). Used by GUI to draw
    /// a "last updated" tooltip; combined with per-component
    /// `updated_at_epoch_secs` for freshness display.
    pub snapshot_refreshed_at_epoch_secs: u64,
    /// `true` when the GUI should show a "snapshot may be stale"
    /// banner — set when at least one component's `updated_at` is
    /// older than `stale_after_secs`.
    pub stale: bool,
}

// ── Aggregator ───────────────────────────────────────────────────────────────

/// In-memory health aggregator. Cheap to clone — internally guarded by
/// a `Mutex` so it can be shared across the bootstrap thread, IPC
/// handlers, and the runtime loop without external synchronisation.
pub struct HealthAggregator {
    inner: Mutex<HealthAggregatorInner>,
}

struct HealthAggregatorInner {
    /// Per-component status, keyed by slug-ordered component id for
    /// stable iteration.
    components: BTreeMap<HealthComponent, HealthComponentSnapshot>,
    /// Optional SCM-lifecycle override (Starting / Stopping / Disabled).
    /// When `Some`, takes precedence over the component-derived state.
    lifecycle_override: Option<ServiceRuntimeState>,
    /// Current policy state. Independently tracked so a `NoState` /
    /// `RecoveryRequired` outcome remains visible to the GUI even when
    /// no Policy component severity has been recorded yet.
    policy_state: ServicePolicyState,
    current_revision: Option<ActiveRevisionState>,
    /// How long a component status can sit untouched before the snapshot
    /// flips its `stale` flag.
    stale_after_secs: u64,
}

impl HealthAggregator {
    /// `stale_after_secs` defaults to 30s, matching the typical GUI
    /// poll cadence (block 14.5 negotiation defaults). Override via
    /// `with_stale_threshold` for tests.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HealthAggregatorInner {
                components: BTreeMap::new(),
                lifecycle_override: Some(ServiceRuntimeState::Starting),
                policy_state: ServicePolicyState::NoState,
                current_revision: None,
                stale_after_secs: 30,
            }),
        }
    }

    pub fn with_stale_threshold(self, secs: u64) -> Self {
        if let Ok(mut inner) = self.inner.lock() {
            inner.stale_after_secs = secs;
        }
        self
    }

    // ── Lifecycle overrides ──────────────────────────────────────────────

    pub fn mark_starting(&self) {
        self.set_lifecycle_override(Some(ServiceRuntimeState::Starting));
    }
    /// Clears the override so component severities drive the state.
    pub fn clear_lifecycle_override(&self) {
        self.set_lifecycle_override(None);
    }
    pub fn mark_stopping(&self) {
        self.set_lifecycle_override(Some(ServiceRuntimeState::Stopping));
    }
    pub fn mark_stopped(&self) {
        self.set_lifecycle_override(Some(ServiceRuntimeState::Stopped));
    }
    pub fn mark_disabled(&self) {
        self.set_lifecycle_override(Some(ServiceRuntimeState::Disabled));
    }

    fn set_lifecycle_override(&self, value: Option<ServiceRuntimeState>) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.lifecycle_override = value;
        }
    }

    // ── Component recording ─────────────────────────────────────────────

    pub fn record(
        &self,
        component: HealthComponent,
        severity: ServiceHealthSeverity,
        message: impl Into<String>,
    ) {
        let now = epoch_secs();
        if let Ok(mut inner) = self.inner.lock() {
            inner.components.insert(
                component,
                HealthComponentSnapshot {
                    component,
                    severity,
                    message: message.into(),
                    updated_at_epoch_secs: now,
                },
            );
        }
    }

    /// Record a complete bootstrap report. Maps each phase severity to
    /// its component (storage/policy/diagnostics) and records the
    /// worst severity per component so the GUI's storage card reflects
    /// e.g. cache rebuild + state-DB OK as `Warning`.
    pub fn record_bootstrap(&self, report: &BootstrapReport) {
        let mut storage = ServiceHealthSeverity::Ok;
        let mut diagnostics = ServiceHealthSeverity::Ok;
        let mut policy = ServiceHealthSeverity::Ok;
        let mut storage_msg = String::new();
        let mut diagnostics_msg = String::new();
        let mut policy_msg = String::new();
        for phase in &report.phases {
            let (bucket, msg_bucket) = match phase.phase {
                "topology" | "directory-acl" | "storage-open-state" | "storage-open-cache"
                | "migrations-state" | "migrations-cache" => (&mut storage, &mut storage_msg),
                "diagnostics-init-audit" | "diagnostics-init-logs" => {
                    (&mut diagnostics, &mut diagnostics_msg)
                }
                "integrity-verify" => (&mut policy, &mut policy_msg),
                _ => continue,
            };
            if phase.severity > *bucket {
                *bucket = phase.severity;
                *msg_bucket = format!("{}: {}", phase.phase, phase.message);
            }
        }
        self.record(
            HealthComponent::Storage,
            storage,
            default_msg(&storage_msg, "storage healthy"),
        );
        self.record(
            HealthComponent::Diagnostics,
            diagnostics,
            default_msg(&diagnostics_msg, "diagnostics healthy"),
        );
        self.record(
            HealthComponent::Policy,
            policy,
            default_msg(&policy_msg, "policy phase healthy"),
        );
    }

    /// Record the policy-loader outcome. Updates `policy_state` and
    /// `current_revision` regardless of the policy component severity
    /// (`NoState` is not a Blocking error, so the policy component
    /// stays at Ok — but the policy_state still flips to NoState).
    pub fn record_policy(&self, outcome: &PolicyLoadResult) {
        let now = epoch_secs();
        if let Ok(mut inner) = self.inner.lock() {
            inner.policy_state = outcome.to_policy_state();
            inner.current_revision = outcome.current_revision().cloned();
            let (severity, msg) = match outcome {
                PolicyLoadResult::ActiveLoaded(s) => (
                    ServiceHealthSeverity::Ok,
                    format!("active revision loaded: {}", s.revision_id),
                ),
                PolicyLoadResult::LkgFallbackApplied(s) => (
                    ServiceHealthSeverity::Warning,
                    format!("active recovered from LKG: {}", s.revision_id),
                ),
                PolicyLoadResult::NoActiveRevision => (
                    ServiceHealthSeverity::Ok,
                    "no active revision yet (first run)".to_string(),
                ),
                PolicyLoadResult::RecoveryRequired(msg) => (
                    ServiceHealthSeverity::Blocking,
                    format!("recovery required: {msg}"),
                ),
                PolicyLoadResult::StorageError(msg) => (
                    ServiceHealthSeverity::Blocking,
                    format!("policy storage error: {msg}"),
                ),
            };
            inner.components.insert(
                HealthComponent::Policy,
                HealthComponentSnapshot {
                    component: HealthComponent::Policy,
                    severity,
                    message: msg,
                    updated_at_epoch_secs: now,
                },
            );
        }
    }

    // ── Snapshot ─────────────────────────────────────────────────────────

    /// Build a fresh snapshot from the current component table. Cheap
    /// — O(N) over component count.
    pub fn snapshot(&self) -> ServiceSnapshot {
        let now = epoch_secs();
        let inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return self.poisoned_snapshot(now),
        };
        let mut components: Vec<HealthComponentSnapshot> =
            inner.components.values().cloned().collect();
        components.sort_by_key(|c| c.component);
        let worst = components
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(ServiceHealthSeverity::Unknown);
        let derived_state = match worst {
            ServiceHealthSeverity::Ok | ServiceHealthSeverity::Warning => {
                ServiceRuntimeState::Running
            }
            ServiceHealthSeverity::Degraded => ServiceRuntimeState::Degraded,
            ServiceHealthSeverity::Blocking => ServiceRuntimeState::RecoveryRequired,
            ServiceHealthSeverity::Unknown => ServiceRuntimeState::Starting,
        };
        let state = inner.lifecycle_override.unwrap_or(derived_state);
        let stale = components
            .iter()
            .any(|c| c.updated_at_epoch_secs + inner.stale_after_secs < now);
        ServiceSnapshot {
            state,
            worst_severity: worst,
            components,
            current_revision: inner.current_revision.clone(),
            policy_state: inner.policy_state,
            snapshot_refreshed_at_epoch_secs: now,
            stale,
        }
    }

    fn poisoned_snapshot(&self, now: u64) -> ServiceSnapshot {
        ServiceSnapshot {
            state: ServiceRuntimeState::RecoveryRequired,
            worst_severity: ServiceHealthSeverity::Blocking,
            components: Vec::new(),
            current_revision: None,
            policy_state: ServicePolicyState::RecoveryRequired,
            snapshot_refreshed_at_epoch_secs: now,
            stale: true,
        }
    }
}

impl Default for HealthAggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthReporter for HealthAggregator {
    fn current_state(&self) -> ServiceRuntimeState {
        self.snapshot().state
    }
    fn worst_severity(&self) -> ServiceHealthSeverity {
        self.snapshot().worst_severity
    }
    fn components(&self) -> Vec<(&'static str, ServiceHealthSeverity, String)> {
        self.snapshot()
            .components
            .into_iter()
            .map(|c| (c.component.slug(), c.severity, c.message))
            .collect()
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_msg(real: &str, fallback: &'static str) -> String {
    if real.is_empty() {
        fallback.to_string()
    } else {
        real.to_string()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managers::BootstrapPhaseStatus;

    fn phase(slug: &'static str, severity: ServiceHealthSeverity) -> BootstrapPhaseStatus {
        BootstrapPhaseStatus {
            phase: slug,
            severity,
            message: "test".into(),
        }
    }

    #[test]
    fn fresh_aggregator_reports_starting_state() {
        let agg = HealthAggregator::new();
        let snap = agg.snapshot();
        assert_eq!(snap.state, ServiceRuntimeState::Starting);
        // Worst severity is Unknown because no component has reported
        // anything yet.
        assert_eq!(snap.worst_severity, ServiceHealthSeverity::Unknown);
    }

    #[test]
    fn worst_severity_is_max_across_components() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        agg.record(
            HealthComponent::Diagnostics,
            ServiceHealthSeverity::Warning,
            "ok-warn",
        );
        agg.record(
            HealthComponent::Ipc,
            ServiceHealthSeverity::Degraded,
            "ipc degraded",
        );
        let snap = agg.snapshot();
        assert_eq!(snap.worst_severity, ServiceHealthSeverity::Degraded);
        assert_eq!(snap.state, ServiceRuntimeState::Degraded);
    }

    #[test]
    fn blocking_severity_maps_to_recovery_required() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record(
            HealthComponent::Storage,
            ServiceHealthSeverity::Blocking,
            "state DB unavailable",
        );
        let snap = agg.snapshot();
        assert_eq!(snap.state, ServiceRuntimeState::RecoveryRequired);
    }

    #[test]
    fn lifecycle_override_takes_precedence() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        // No override -> Running.
        assert_eq!(agg.snapshot().state, ServiceRuntimeState::Running);
        // Stopping override should win even though components are Ok.
        agg.mark_stopping();
        assert_eq!(agg.snapshot().state, ServiceRuntimeState::Stopping);
        // Stopped override holds.
        agg.mark_stopped();
        assert_eq!(agg.snapshot().state, ServiceRuntimeState::Stopped);
    }

    #[test]
    fn record_bootstrap_buckets_phases_into_components() {
        let agg = HealthAggregator::new();
        let report = BootstrapReport {
            phases: vec![
                phase("topology", ServiceHealthSeverity::Ok),
                phase("storage-open-state", ServiceHealthSeverity::Ok),
                phase("storage-open-cache", ServiceHealthSeverity::Warning),
                phase("diagnostics-init-audit", ServiceHealthSeverity::Ok),
                phase("diagnostics-init-logs", ServiceHealthSeverity::Degraded),
                phase("integrity-verify", ServiceHealthSeverity::Ok),
            ],
            worst_severity: ServiceHealthSeverity::Degraded,
            blocking: false,
        };
        agg.record_bootstrap(&report);
        agg.clear_lifecycle_override();
        let snap = agg.snapshot();
        let by: BTreeMap<HealthComponent, ServiceHealthSeverity> = snap
            .components
            .iter()
            .map(|c| (c.component, c.severity))
            .collect();
        assert_eq!(
            by[&HealthComponent::Storage],
            ServiceHealthSeverity::Warning
        );
        assert_eq!(
            by[&HealthComponent::Diagnostics],
            ServiceHealthSeverity::Degraded
        );
        assert_eq!(by[&HealthComponent::Policy], ServiceHealthSeverity::Ok);
        // Storage Warning + Diagnostics Degraded → Degraded overall.
        assert_eq!(snap.state, ServiceRuntimeState::Degraded);
    }

    #[test]
    fn record_policy_no_active_keeps_policy_state_no_state() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record_policy(&PolicyLoadResult::NoActiveRevision);
        let snap = agg.snapshot();
        assert_eq!(snap.policy_state, ServicePolicyState::NoState);
        assert!(snap.current_revision.is_none());
    }

    #[test]
    fn record_policy_lkg_fallback_marks_warning_and_keeps_summary() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        let summary = ActiveRevisionState {
            revision_id: "rev-lkg".into(),
            provenance: "recovery-fallback".into(),
            rule_count: 0,
            behavior_mode: "auto".into(),
            content_hash_hex: "deadbeef".into(),
            activated_at_iso: "t".into(),
        };
        agg.record_policy(&PolicyLoadResult::LkgFallbackApplied(summary.clone()));
        let snap = agg.snapshot();
        assert_eq!(snap.policy_state, ServicePolicyState::LkgReady);
        assert_eq!(snap.current_revision, Some(summary));
        let policy = snap
            .components
            .iter()
            .find(|c| c.component == HealthComponent::Policy)
            .unwrap();
        assert_eq!(policy.severity, ServiceHealthSeverity::Warning);
    }

    #[test]
    fn record_policy_recovery_required_blocks() {
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record_policy(&PolicyLoadResult::RecoveryRequired("no LKG".into()));
        let snap = agg.snapshot();
        assert_eq!(snap.state, ServiceRuntimeState::RecoveryRequired);
        assert_eq!(snap.policy_state, ServicePolicyState::RecoveryRequired);
    }

    #[test]
    fn stale_marker_flips_when_component_is_old() {
        let agg = HealthAggregator::new().with_stale_threshold(0);
        agg.clear_lifecycle_override();
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        // Sleep one second so updated_at + 0 < now. We can't sleep
        // long in unit tests; instead exploit threshold = 0 — every
        // component is stale the moment we ask, even on the same epoch
        // tick, because the inequality is `updated + threshold < now`,
        // not `<=`. Force the gap via a small sleep.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let snap = agg.snapshot();
        assert!(
            snap.stale,
            "expected stale=true for old component: {snap:?}"
        );
    }

    #[test]
    fn snapshot_components_are_sorted_for_stable_diffs() {
        let agg = HealthAggregator::new();
        agg.record(HealthComponent::Ipc, ServiceHealthSeverity::Ok, "ok");
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        agg.record(HealthComponent::Adapters, ServiceHealthSeverity::Ok, "ok");
        let snap = agg.snapshot();
        let order: Vec<HealthComponent> = snap.components.iter().map(|c| c.component).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
    }

    #[test]
    fn audit_unavailable_blocks_overall_severity_to_blocking() {
        // Diagnostics Blocking → snapshot reports RecoveryRequired even
        // when storage and policy are both Ok. This is the
        // "audit unavailable -> mutation blocked" check from the task
        // list — the IPC layer (block 14.5) refuses mutating ops when
        // the snapshot reports Blocking.
        let agg = HealthAggregator::new();
        agg.clear_lifecycle_override();
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        agg.record(HealthComponent::Policy, ServiceHealthSeverity::Ok, "ok");
        agg.record(
            HealthComponent::Diagnostics,
            ServiceHealthSeverity::Blocking,
            "audit dir unwritable",
        );
        let snap = agg.snapshot();
        assert_eq!(snap.worst_severity, ServiceHealthSeverity::Blocking);
        assert_eq!(snap.state, ServiceRuntimeState::RecoveryRequired);
    }

    #[test]
    fn snapshot_is_pure_observation_not_mutation() {
        // Pinning task 14.6 invariant: snapshot() must not mutate state.
        let agg = HealthAggregator::new();
        agg.record(HealthComponent::Storage, ServiceHealthSeverity::Ok, "ok");
        let s1 = agg.snapshot();
        let s2 = agg.snapshot();
        // Components / severities / policy_state stable across calls;
        // only `snapshot_refreshed_at_epoch_secs` may differ.
        assert_eq!(s1.components, s2.components);
        assert_eq!(s1.policy_state, s2.policy_state);
        assert_eq!(s1.worst_severity, s2.worst_severity);
    }
}
